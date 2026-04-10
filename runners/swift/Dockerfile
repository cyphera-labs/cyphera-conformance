FROM swift:6.0 AS builder
WORKDIR /app
COPY Package.swift .
COPY Sources Sources/
RUN swift build -c release

FROM swift:6.0-slim
COPY --from=builder /app/.build/release/run /usr/local/bin/run
WORKDIR /vectors
CMD ["run"]
