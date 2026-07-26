# E2E workstation ("human"): openssh-client + gssh binary (placed into the
# build context by the test). The entrypoint starts a long-lived ssh-agent —
# gssh login loads the certificate there, ssh uses it transparently.
FROM alpine:3.22

RUN apk add --no-cache openssh-client bash curl

COPY gssh /usr/local/bin/gssh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/gssh

ENTRYPOINT ["/entrypoint.sh"]
