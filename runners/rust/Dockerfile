FROM rust:1.78-slim
WORKDIR /app
COPY . .
RUN cargo build --release -q
WORKDIR /vectors
CMD ["/app/target/release/cyphera-test-runner"]
