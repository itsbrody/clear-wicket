# SPDX-License-Identifier: Apache-2.0
FROM golang:1.25-alpine AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /clear-wicket ./cmd/clear-wicket

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /clear-wicket /clear-wicket
USER 65534:65534
EXPOSE 4181
HEALTHCHECK --interval=30s --timeout=3s CMD ["/clear-wicket", "healthcheck"]
ENTRYPOINT ["/clear-wicket"]
