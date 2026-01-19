FROM rust:1.84 as builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

COPY --from=builder /app/target/release/x-dns /usr/local/bin/x-dns

EXPOSE 53/udp
EXPOSE 4080

ENTRYPOINT ["/usr/local/bin/x-dns"]
