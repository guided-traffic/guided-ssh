# Test host for the phase 5/7/E integration tests: alpine + sshd + two local
# users (alice: principal match, deploy: grant and CI path).
# python3: target interpreter for the ansible ping in the phase 7 E2E test.
# curl + ca-certificates: the one-command install's install.sh requires curl
# (alpine doesn't ship one) and downloads over HTTPS.
FROM alpine:3.24

RUN apk add --no-cache openssh-server bash python3 curl ca-certificates \
    && ssh-keygen -A \
    && adduser -D -s /bin/sh alice \
    && adduser -D -s /bin/sh deploy \
    # adduser -D locks accounts ("!"); "*" allows pubkey login without a password.
    && sed -i 's/^alice:!/alice:*/; s/^deploy:!/deploy:*/' /etc/shadow \
    && mkdir -p /etc/ssh/sshd_config.d /var/lib/guided-ssh \
    && sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config \
    # PerSourcePenalties (OpenSSH >= 9.8) would lock out the test retries.
    && printf 'PasswordAuthentication no\nLogLevel VERBOSE\nPerSourcePenalties no\n' >> /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
