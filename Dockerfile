# Build-Stage
FROM golang:1.26 AS build
WORKDIR /src

# Abhängigkeiten zuerst, für Layer-Caching (go.sum entsteht mit der ersten externen Dependency)
COPY go.* ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X github.com/guided-traffic/guided-ssh/internal/version.version=${VERSION} \
        -X github.com/guided-traffic/guided-ssh/internal/version.commit=${COMMIT} \
        -X github.com/guided-traffic/guided-ssh/internal/version.date=${DATE}" \
      -o /out/gssh-server ./cmd/gssh-server

# Runtime-Stage: distroless, non-root, nur das statische Binary
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gssh-server /usr/local/bin/gssh-server
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/gssh-server"]
