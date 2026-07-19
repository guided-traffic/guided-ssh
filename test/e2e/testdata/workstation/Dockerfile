# E2E-Workstation ("Mensch"): openssh-client + gssh-Binary (vom Test in den
# Build-Kontext gelegt). Der Entrypoint startet einen langlebigen ssh-agent —
# gssh login lädt das Zertifikat dorthin, ssh benutzt es transparent.
FROM alpine:3.22

RUN apk add --no-cache openssh-client bash curl

COPY gssh /usr/local/bin/gssh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/gssh

ENTRYPOINT ["/entrypoint.sh"]
