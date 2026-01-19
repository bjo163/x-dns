use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Instant, Duration};

use tokio::net::UdpSocket;
use tokio::time::timeout;

use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Record, RData};
use trust_dns_proto::rr::rdata::A;
use trust_dns_proto::serialize::binary::*;

use once_cell::sync::Lazy;

use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use serde::Serialize;

/* =========================
   GLOBAL STATS
========================= */
#[derive(Default, Serialize)]
struct Stats {
    total_queries: u64,
    cache_hits: u64,
    cache_misses: u64,
    errors: u64,
    per_domain: HashMap<String, u64>,
    per_client: HashMap<String, u64>,
}

impl Stats {
    fn inc_domain(&mut self, domain: &str) {
        let c = self.per_domain.entry(domain.to_string()).or_insert(0);
        *c += 1;
    }

    fn inc_client(&mut self, ip: &str) {
        let c = self.per_client.entry(ip.to_string()).or_insert(0);
        *c += 1;
    }
}

static STATS: Lazy<Mutex<Stats>> = Lazy::new(|| Mutex::new(Stats::default()));

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dns_addr: SocketAddr = "0.0.0.0:53".parse()?;
    let socket = UdpSocket::bind(dns_addr).await?;
    println!("DNS server running on {}", dns_addr);

    // start http stats server in background
    tokio::spawn(async {
        start_http_stats().await.unwrap();
    });

    let mut buf = [0u8; 512];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("recv_from error: {}", e);
                STATS.lock().unwrap().errors += 1;
                continue;
            }
        };

        // parse DNS request
        let req = match Message::from_vec(&buf[..len]) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("parse error: {}", e);
                STATS.lock().unwrap().errors += 1;
                continue;
            }
        };

        let query = match req.queries().first() {
            Some(q) => q,
            None => continue,
        };

        let name = query.name().to_string();

        // update stats
        {
            let mut st = STATS.lock().unwrap();
            st.total_queries += 1;
            st.inc_domain(&name);
            st.inc_client(&src.ip().to_string());
        }

        // rate limit per IP
        if !RATE_LIMIT.lock().unwrap().check(&src) {
            println!("Rate limit exceeded: {}", src);
            continue;
        }

        println!("Query: {}", name);

        // 1) Cache check
        if let Some(resp) = CACHE.lock().unwrap().get(&name) {
            let _ = socket.send_to(&resp, &src).await;
            STATS.lock().unwrap().cache_hits += 1;
            continue;
        }

        STATS.lock().unwrap().cache_misses += 1;

        // 2) Hardcode domain tertentu
        if name == "example.com." {
            let resp = build_response(&req, query, "1.2.3.4".parse().unwrap());
            let _ = socket.send_to(&resp, &src).await;
            continue;
        }

        // 3) Forward ke upstream 8.8.8.8 (Google)
        if let Some(resp) = forward_query(&buf[..len], "8.8.8.8:53").await {
            CACHE.lock().unwrap().set(&name, resp.clone());
            let _ = socket.send_to(&resp, &src).await;
            continue;
        }

        // 4) Kalau gagal, forward ke Cloudflare 1.1.1.1
        if let Some(resp) = forward_query(&buf[..len], "1.1.1.1:53").await {
            CACHE.lock().unwrap().set(&name, resp.clone());
            let _ = socket.send_to(&resp, &src).await;
            continue;
        }

        // kalau gagal semua, ignore
        println!("Failed to resolve: {}", name);
    }
}

/* =========================
   HTTP STATS SERVER
========================= */
async fn start_http_stats() -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));

    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, hyper::Error>(service_fn(stats_handler))
    });

    let server = Server::bind(&addr).serve(make_svc);
    println!("Stats HTTP running on http://{}", addr);

    server.await?;
    Ok(())
}

async fn stats_handler(_req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let st = STATS.lock().unwrap();
    let json = serde_json::to_string(&*st).unwrap();
    Ok(Response::new(Body::from(json)))
}

/* =========================
   MODULE: CACHE SIMPLE
========================= */
struct CacheEntry {
    data: Vec<u8>,
    expire_at: Instant,
}

struct SimpleCache {
    map: HashMap<String, CacheEntry>,
    ttl: Duration,
}

impl SimpleCache {
    fn new(ttl_seconds: u64) -> Self {
        Self {
            map: HashMap::new(),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        if let Some(entry) = self.map.get(key) {
            if entry.expire_at > Instant::now() {
                return Some(entry.data.clone());
            }
        }
        None
    }

    fn set(&mut self, key: &str, data: Vec<u8>) {
        self.map.insert(key.to_string(), CacheEntry {
            data,
            expire_at: Instant::now() + self.ttl,
        });
    }
}

static CACHE: Lazy<Mutex<SimpleCache>> = Lazy::new(|| {
    Mutex::new(SimpleCache::new(30))
});

/* =========================
   MODULE: RATE LIMIT SIMPLE
========================= */
struct RateLimitEntry {
    last: Instant,
    count: u32,
}

struct RateLimit {
    map: HashMap<String, RateLimitEntry>,
    limit: u32,
    window: Duration,
}

impl RateLimit {
    fn new(limit: u32, window_seconds: u64) -> Self {
        Self {
            map: HashMap::new(),
            limit,
            window: Duration::from_secs(window_seconds),
        }
    }

    fn check(&mut self, addr: &SocketAddr) -> bool {
        let key = addr.ip().to_string();
        let now = Instant::now();

        let entry = self.map.entry(key).or_insert(RateLimitEntry {
            last: now,
            count: 0,
        });

        // reset if window expired
        if now.duration_since(entry.last) > self.window {
            entry.count = 0;
            entry.last = now;
        }

        if entry.count >= self.limit {
            return false;
        }

        entry.count += 1;
        true
    }
}

static RATE_LIMIT: Lazy<Mutex<RateLimit>> = Lazy::new(|| {
    Mutex::new(RateLimit::new(10, 1)) // 10 req per detik
});

/* =========================
   MODULE: FORWARDER
========================= */
async fn forward_query(query_bytes: &[u8], upstream: &str) -> Option<Vec<u8>> {
    let upstream_addr: SocketAddr = upstream.parse().ok()?;
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;

    socket.send_to(query_bytes, upstream_addr).await.ok()?;

    let mut resp_buf = [0u8; 512];

    let len = match timeout(Duration::from_secs(2), socket.recv_from(&mut resp_buf)).await {
        Ok(Ok((len, _addr))) => len,
        Ok(Err(e)) => {
            // Windows: ignore ICMP port unreachable
            if e.raw_os_error() == Some(10054) {
                return None;
            }
            return None;
        }
        _ => return None,
    };

    Some(resp_buf[..len].to_vec())
}

/* =========================
   MODULE: RESPONSE BUILDER
========================= */
fn build_response(req: &Message, query: &Query, ip: std::net::Ipv4Addr) -> Vec<u8> {
    let mut resp = Message::new();
    resp.set_id(req.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_authoritative(true);
    resp.add_query(Query::query(query.name().clone(), query.query_type()));

    let octets = ip.octets();
    let record = Record::from_rdata(
        query.name().clone(),
        60,
        RData::A(A::new(octets[0], octets[1], octets[2], octets[3])),
    );

    resp.add_answer(record);

    let mut resp_buf = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut resp_buf);
    resp.emit(&mut encoder).unwrap();
    resp_buf
}
