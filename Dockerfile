# Build stage. Pinned so that a rebuild months from now produces the same
# binary rather than a subtly different dependency graph.
FROM golang:1.26-alpine AS build

# CGO is off throughout: the SQLite driver is modernc, which is pure Go, so
# the result is a static binary with no libc dependency to reason about.
ENV CGO_ENABLED=0 GOOS=linux

WORKDIR /src

# Dependencies are copied and downloaded first so the module cache survives
# source edits. Without this every code change re-downloads the whole graph.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# -trimpath strips the build machine's directory layout out of the binary.
ARG VERSION=dev
RUN go build -trimpath -mod=readonly \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/bugbounty ./cmd/bugbounty

# Run the tests as part of the image build. A container that ships a broken
# binary is worse than no container, and `docker build` is the only place a
# user is guaranteed to be running this.
RUN go vet ./...
RUN go test -count=1 ./...


FROM gcr.io/distroless/static-debian12:nonroot

# Certificates, so TLS verification of real targets works. The
# certificate-bearing image is used rather than the static one precisely for
# this: a scanner that cannot validate a certificate either fails every
# handshake or is tempted to turn verification off.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/bugbounty /bugbounty

# Nothing here needs to be written to the image. The database and the reports
# belong on a volume the operator controls, because they contain the
# engagement's findings.
VOLUME ["/data"]
WORKDIR /data

USER nonroot:nonroot

ENTRYPOINT ["/bugbounty"]
CMD ["--help"]
