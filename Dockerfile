ARG BUILDPLATFORM=linux/amd64

# Precompile key slow-to-build dependencies
FROM --platform=$BUILDPLATFORM golang:1.20 as go-deps
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
ARG TARGETARCH

## compile controller service
FROM go-deps as golang
WORKDIR /build
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build -o /out/controller -tags prod -mod=readonly -ldflags "-s -w" .

## package runtime
FROM scratch
COPY LICENSE /linkerd/LICENSE
COPY --from=golang /out/controller /controller
# for heartbeat (https://versioncheck.linkerd.io/version.json)
COPY --from=golang /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/controller"]
