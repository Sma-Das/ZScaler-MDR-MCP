FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go/go.mod go/go.sum ./
RUN go mod download && go mod verify
COPY go/ ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w -X github.com/Sma-Das/ZScaler-MDR-MCP/go/internal/mcpserver.Version=$VERSION" \
    -o /out/zscaler-mdr-mcp ./cmd/server

FROM scratch
ENV HOST=0.0.0.0 PORT=3000
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/zscaler-mdr-mcp /usr/local/bin/zscaler-mdr-mcp
USER 65534:65534
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/local/bin/zscaler-mdr-mcp", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/zscaler-mdr-mcp"]
