FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795 AS build
RUN apk add --no-cache go-1.22 && rm -rf /var/cache/apk/*
ENV PATH="/usr/lib/go-1.22/bin:$PATH"
WORKDIR /app
COPY . .
RUN go build -o runner .

FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
COPY --from=build /app/runner /app/runner
WORKDIR /vectors
CMD ["/app/runner"]
