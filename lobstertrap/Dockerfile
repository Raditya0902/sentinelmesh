FROM golang:1.23-alpine AS builder

WORKDIR /app

# Build context is the repo root (docker-compose.yml: context: .), so all
# Go source lives under lobstertrap/.  Copy the module files first for a
# cacheable download layer, then the full source tree.
COPY lobstertrap/go.mod lobstertrap/go.sum ./
RUN go mod download

COPY lobstertrap/ .
RUN CGO_ENABLED=0 GOOS=linux go build -o lobstertrap .

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/lobstertrap /usr/local/bin/lobstertrap
COPY lobstertrap/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN mkdir -p /etc/lobstertrap /app/logs
COPY proxy/policy.yaml /etc/lobstertrap/policy.yaml

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
