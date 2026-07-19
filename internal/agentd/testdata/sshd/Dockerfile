# Test-Host für den Phase-5-Integrationstest: alpine + sshd + zwei lokale
# Benutzer (alice: Principal-Match, deploy: Grant-Pfad).
FROM alpine:3.22

RUN apk add --no-cache openssh-server bash \
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
