# Workstation fixture for the client.sh E2E test: alpine + curl +
# ca-certificates (the script downloads over HTTPS) and a non-root user —
# the script refuses root, so alice's home is where binary and config land.
FROM alpine:3.24

RUN apk add --no-cache curl ca-certificates \
    && adduser -D -s /bin/sh alice

CMD ["sh", "-c", "echo 'workstation ready'; exec tail -f /dev/null"]
