FROM swift:5.10 AS builder
WORKDIR /app
COPY Package.swift .
COPY Sources Sources/
RUN swift build -c release -q

FROM swift:5.10-slim
COPY --from=builder /app/.build/release/run /usr/local/bin/run
WORKDIR /vectors
CMD ["run"]
