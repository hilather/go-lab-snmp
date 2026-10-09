# LabSNMP production image: ghcr.io/hilather/labsnmp
#
# Multi-stage, static binary, numeric non-root UID, no shell.
# No Node stage — UI-001 embeds dist/ on the host.
# Appliance smoke uses --snmp-listen=:1161 --trap-listen=:1162 and cap_drop ALL.
# Integrator compose restores only NET_BIND_SERVICE so bind-to-161/162 works.

FROM golang:1.26.9-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build -trimpath \
	-ldflags="-s -w \
	-X github.com/hilather/go-lab-snmp/internal/buildinfo.version=${VERSION} \
	-X github.com/hilather/go-lab-snmp/internal/buildinfo.commit=${COMMIT} \
	-X github.com/hilather/go-lab-snmp/internal/buildinfo.buildTime=${BUILD_TIME}" \
	-o /out/labsnmp ./cmd/labsnmp \
	&& printf 'labsnmp:x:65532:65532:labsnmp:/:/sbin/nologin\n' > /out/passwd \
	&& printf 'labsnmp:x:65532:\n' > /out/group \
	&& cp /etc/ssl/certs/ca-certificates.crt /out/ca-certificates.crt \
	&& cp LICENSE /out/LICENSE

FROM scratch

LABEL org.opencontainers.image.title="labsnmp" \
	org.opencontainers.image.description="Laboratory SNMPv1/v2c/v3 agent with a receive-only trap/inform sink" \
	org.opencontainers.image.source="https://github.com/hilather/go-lab-snmp" \
	org.opencontainers.image.url="https://github.com/hilather/go-lab-snmp" \
	org.opencontainers.image.licenses="Apache-2.0" \
	org.opencontainers.image.vendor="hilather" \
	org.opencontainers.image.documentation="https://github.com/hilather/go-lab-snmp/blob/main/docs/11-deployment.md"

COPY --from=build /out/passwd /etc/passwd
COPY --from=build /out/group /etc/group
COPY --from=build /out/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/labsnmp /labsnmp
COPY --from=build /out/LICENSE /LICENSE

USER 65532:65532
EXPOSE 161/udp 162/udp 161/tcp 162/tcp 8088/tcp
WORKDIR /

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
	CMD ["/labsnmp", "healthcheck", "--url=http://127.0.0.1:8088/v1/health/ready"]

ENTRYPOINT ["/labsnmp"]
# serve --management-listen defaults to off (SNMP-only). The image must bind
# management so HEALTHCHECK and authenticated /v1 work from the published 8088.
CMD ["serve", "--config=/etc/labsnmp/config.yaml", "--management-listen=:8088"]
