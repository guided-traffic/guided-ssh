# E2E test host: alpine + sshd + gssh-agentd (binary is placed into the
# build context by the test). Users like in the Phase 5/7 integration test:
# alice (principal match), deploy (grant and CI path); python3 for Ansible.
FROM alpine:3.22

RUN apk add --no-cache openssh-server bash python3 \
    && adduser -D -s /bin/sh alice \
    && adduser -D -s /bin/sh deploy \
    # adduser -D locks accounts ("!"); "*" allows pubkey login without a password.
    && sed -i 's/^alice:!/alice:*/; s/^deploy:!/deploy:*/' /etc/shadow \
    && mkdir -p /etc/ssh/sshd_config.d /var/lib/guided-ssh \
    && sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config \
    # PerSourcePenalties (OpenSSH >= 9.8) would lock out the test retries.
    && printf 'PasswordAuthentication no\nLogLevel VERBOSE\nPerSourcePenalties no\n' >> /etc/ssh/sshd_config

COPY gssh-agentd /usr/local/bin/gssh-agentd
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/gssh-agentd

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
