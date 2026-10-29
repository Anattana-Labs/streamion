# syntax=docker/dockerfile:1

# Stage 1: Build Go binaries (Warp & SOCKS5 Server)
FROM golang:1.24-alpine AS go-builder
WORKDIR /go/src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags '-s -w' -o /warp ./cmd/warp \
    && CGO_ENABLED=0 GOOS=linux go build -ldflags '-s -w' -o /server ./cmd/server

# Stage 2: Deno binary
FROM denoland/deno:bin-2.9.7 AS deno-bin

# Stage 3: Runtime
FROM debian:12-slim AS runner

EXPOSE 25023 8080

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    ca-certificates \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries
COPY --from=go-builder /warp /usr/local/bin/warp
COPY --from=go-builder /server /usr/local/bin/server
COPY --from=deno-bin /deno /usr/local/bin/deno

# Create cache directory for youtubei.js
RUN mkdir -p /var/tmp/youtubei.js

# Copy app files
WORKDIR /app
COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

COPY deno.json compile.env grafana_dashboard.json ./
COPY config ./config
COPY src ./src

# Environment variables
ENV PORT=25023
ENV HOST="0.0.0.0"
ENV SOCKS_PORT=1080
ENV WIREGUARD_INTERFACE_DNS="1.1.1.1"
ENV DENO_DIR="/tmp/deno_cache"

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]