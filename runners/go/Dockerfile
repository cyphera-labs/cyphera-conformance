FROM golang:1.22-bookworm
WORKDIR /app
COPY . .
RUN go build -o runner .
WORKDIR /vectors
CMD ["/app/runner"]
