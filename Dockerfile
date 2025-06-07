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
COPY --from=builder /app/uploads ./uploads



ADD https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh

EXPOSE 8080

CMD ["bash", "/wait-for-it.sh", "db:3306", "--", "./smartstudy"]