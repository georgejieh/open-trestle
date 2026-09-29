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
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/trestled"]
