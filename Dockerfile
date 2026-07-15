# Multi-stage image embedding Bernetes-Buster + kubectl
# SPDX-License-Identifier: AGPL-3.0-or-later
FROM alpine:3.20 AS kubectl
ARG TARGETARCH=amd64
ARG KUBECTL_VERSION=v1.31.4
RUN apk add --no-cache curl ca-certificates \
 && curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" -o /kubectl \
 && chmod +x /kubectl

FROM alpine:3.20
LABEL org.opencontainers.image.title="Bernetes-Buster" \
      org.opencontainers.image.description="LinPEAS-style Kubernetes misconfiguration explorer" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/Maximebb/Bernetes-Buster"

RUN apk add --no-cache bash curl ca-certificates coreutils iproute2 libcap \
 && adduser -D -u 65532 -g 65532 bbuster

COPY --from=kubectl /kubectl /usr/local/bin/kubectl
COPY bbuster.sh /opt/bbuster/bbuster.sh
COPY lib /opt/bbuster/lib
COPY profiles /opt/bbuster/profiles

RUN chmod +x /opt/bbuster/bbuster.sh \
 && mkdir -p /reports \
 && chown -R 65532:65532 /opt/bbuster /reports

WORKDIR /opt/bbuster
USER 65532:65532
ENTRYPOINT ["/opt/bbuster/bbuster.sh"]
CMD ["--profile", "security-eng", "--json", "/reports/bbuster-report.json"]
