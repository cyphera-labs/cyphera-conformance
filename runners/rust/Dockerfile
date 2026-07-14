FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795 AS build
RUN apk add --no-cache rust-1.83 build-base && rm -rf /var/cache/apk/*
WORKDIR /app
COPY . .
RUN cargo build --release -q

FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
RUN apk add --no-cache libgcc && rm -rf /var/cache/apk/*
COPY --from=build /app/target/release/cyphera-test-runner /app/cyphera-test-runner
WORKDIR /vectors
CMD ["/app/cyphera-test-runner"]
