FROM rust:1.83-slim
WORKDIR /app
COPY . .
RUN cargo build --release -q
WORKDIR /vectors
CMD ["/app/target/release/cyphera-test-runner"]
