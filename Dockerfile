### Dockerfile for SmartStudy

# Build stage
FROM golang:1.24-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o smartstudy .

# Final stage
FROM alpine:latest
WORKDIR /app
RUN apk add --no-cache ca-certificates bash

COPY --from=builder /app/smartstudy .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/resource ./resource
RUN mkdir -p /app/uploads/assignments /app/uploads/materials /app/uploads/submissions

EXPOSE 8080

CMD ["./smartstudy"]