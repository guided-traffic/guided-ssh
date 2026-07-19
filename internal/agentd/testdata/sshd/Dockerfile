# Test-Host für die Phase-5/7-Integrationstests: alpine + sshd + zwei lokale
# Benutzer (alice: Principal-Match, deploy: Grant- und CI-Pfad).
# python3: Ziel-Interpreter für den Ansible-Ping im Phase-7-E2E-Test.
FROM alpine:3.22

RUN apk add --no-cache openssh-server bash python3 \
    && ssh-keygen -A \
    && adduser -D -s /bin/sh alice \
    && adduser -D -s /bin/sh deploy \
    # adduser -D sperrt Konten ("!"); "*" erlaubt Pubkey-Login ohne Passwort.
    && sed -i 's/^alice:!/alice:*/; s/^deploy:!/deploy:*/' /etc/shadow \
    && mkdir -p /etc/ssh/sshd_config.d /var/lib/guided-ssh \
    && sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config \
    # PerSourcePenalties (OpenSSH >= 9.8) würde die Test-Retries aussperren.
    && printf 'PasswordAuthentication no\nLogLevel VERBOSE\nPerSourcePenalties no\n' >> /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
