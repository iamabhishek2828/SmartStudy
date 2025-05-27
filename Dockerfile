### Dockerfile for SmartStudy

# 1) Build stage
FROM golang:1.24-alpine AS builder
WORKDIR /app

# Cache Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy and compile
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o smartstudy .

# 2) Final stage
FROM alpine:latest
WORKDIR /app

# Certificates for TLS/SSL
RUN apk add --no-cache ca-certificates

# Copy binary
COPY --from=builder /app/smartstudy .

# Expose port (Railway sets $PORT)
ENV PORT 8080

# Entrypoint
CMD ["/app/smartstudy"]
