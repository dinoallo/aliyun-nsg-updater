# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /aliyun-nsg-updater .

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /aliyun-nsg-updater /usr/local/bin/aliyun-nsg-updater

ENTRYPOINT ["/usr/local/bin/aliyun-nsg-updater"]
