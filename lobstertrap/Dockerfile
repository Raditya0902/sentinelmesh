FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o lobstertrap .

FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/lobstertrap /usr/local/bin/lobstertrap

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/lobstertrap"]
