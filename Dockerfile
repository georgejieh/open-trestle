FROM scratch
COPY .container/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY .container/trestle /usr/local/bin/trestle
COPY .container/trestled /usr/local/bin/trestled
COPY --chown=0:0 --chmod=0555 .container/libexec/open-trestle/open-trestle-secret-scanner /usr/local/libexec/open-trestle/open-trestle-secret-scanner
COPY --chown=0:0 --chmod=0555 .container/libexec/open-trestle/open-trestle-secret-scanner-worker /usr/local/libexec/open-trestle/open-trestle-secret-scanner-worker
COPY .container/LICENSE /licenses/open-trestle/LICENSE
COPY .container/NOTICE /licenses/open-trestle/NOTICE
COPY .container/licenses /licenses/open-trestle/third-party
COPY .container/release /licenses/open-trestle/release
COPY --chown=65532:65532 .container/data /var/lib/open-trestle
USER 65532:65532
WORKDIR /var/lib/open-trestle
# trestled listens on 127.0.0.1:8741 by default, reachable only inside the
# container. Publishing the port needs --listen 0.0.0.0:8741 with --tls-cert and
# --tls-key (a non-loopback address requires TLS); local review mode
# (--local-full-review) requires a loopback address.
EXPOSE 8741
ENTRYPOINT ["/usr/local/bin/trestled"]
