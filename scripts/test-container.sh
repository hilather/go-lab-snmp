#!/usr/bin/env bash
# Container contract. Skip if Docker is missing; fail closed if the daemon
# exists but the image/contract is wrong. Default path: compose.smoke.yaml
# (:1161/:1162, cap_drop ALL, docker compose up --build). Gated path:
# LABSNMP_TEST_NET_BIND=1 runs :161/:162 + NET_BIND_SERVICE (skip if the
# runtime cannot grant the cap).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${LABSNMP_TEST_IMAGE:-ghcr.io/hilather/labsnmp:test}"
PROJECT="labsnmp-ct-$$"
NAME="labsnmp-container-test-$$"
COMPOSE="${ROOT}/examples/compose.smoke.yaml"
TOKEN="${ROOT}/testdata/container/token"
CONFIG="${ROOT}/testdata/container/config.yaml"
COMMUNITY="${ROOT}/testdata/container/community-public"
# Host publish from examples/compose.smoke.yaml
MGMT_PORT=18088
SNMP_PORT=1161
TRAP_PORT=1162

if ! command -v docker >/dev/null 2>&1; then
	echo "skip: docker is not installed" >&2
	exit 0
fi
if ! docker info >/dev/null 2>&1; then
	echo "skip: docker daemon is not available" >&2
	exit 0
fi
if ! command -v curl >/dev/null 2>&1; then
	echo "curl is required for make test-container" >&2
	exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
	echo "docker compose plugin is required for make test-container" >&2
	exit 1
fi
if [ ! -f "${TOKEN}" ] || [ ! -f "${CONFIG}" ] || [ ! -f "${COMMUNITY}" ]; then
	echo "missing testdata/container/{token,config.yaml,community-public}" >&2
	exit 1
fi

cleanup() {
	docker compose -p "${PROJECT}" -f "${COMPOSE}" down --remove-orphans >/dev/null 2>&1 || true
	docker rm -f "${NAME}-bind" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "building ${IMAGE} via ${COMPOSE}"
docker compose -p "${PROJECT}" -f "${COMPOSE}" up --build -d --remove-orphans

inspect_user="$(docker image inspect --format '{{.Config.User}}' "${IMAGE}")"
if [ "${inspect_user}" != "65532:65532" ]; then
	echo "image User=${inspect_user}, want 65532:65532" >&2
	exit 1
fi

licenses="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.licenses"}}' "${IMAGE}")"
if [ "${licenses}" != "Apache-2.0" ]; then
	echo "image license label=${licenses}, want Apache-2.0" >&2
	exit 1
fi

hc="$(docker image inspect --format '{{json .Config.Healthcheck.Test}}' "${IMAGE}")"
case "${hc}" in
*CMD-SHELL*)
	echo "image HEALTHCHECK=${hc} must be exec form, not shell" >&2
	exit 1
	;;
esac
case "${hc}" in
'["CMD",'*)
	;;
*)
	echo "image HEALTHCHECK=${hc}, want JSON array starting with CMD" >&2
	exit 1
	;;
esac
case "${hc}" in
*'/v1/health/ready'*)
	;;
*)
	echo "image HEALTHCHECK=${hc}, want /v1/health/ready" >&2
	exit 1
	;;
esac
case "${hc}" in
*healthcheck*)
	;;
*)
	echo "image HEALTHCHECK=${hc}, want exec-form labsnmp healthcheck" >&2
	exit 1
	;;
esac

cmd="$(docker image inspect --format '{{json .Config.Cmd}}' "${IMAGE}")"
case "${cmd}" in
*'--management-listen=:8088'*)
	;;
*)
	echo "image CMD=${cmd}, want --management-listen=:8088" >&2
	exit 1
	;;
esac

CID="$(docker compose -p "${PROJECT}" -f "${COMPOSE}" ps -q labsnmp)"
if [ -z "${CID}" ]; then
	echo "compose service labsnmp has no container" >&2
	docker compose -p "${PROJECT}" -f "${COMPOSE}" ps >&2 || true
	docker compose -p "${PROJECT}" -f "${COMPOSE}" logs >&2 || true
	exit 1
fi

if [ "$(docker inspect --format '{{.State.Running}}' "${CID}")" != "true" ]; then
	echo "compose container is not running" >&2
	docker inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}' "${CID}" >&2 || true
	docker compose -p "${PROJECT}" -f "${COMPOSE}" logs >&2 || true
	exit 1
fi

readonly_root="$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "${CID}")"
if [ "${readonly_root}" != "true" ]; then
	echo "HostConfig.ReadonlyRootfs=${readonly_root}, want true" >&2
	exit 1
fi

caps="$(docker inspect --format '{{json .HostConfig.CapDrop}}' "${CID}")"
case "${caps}" in
*ALL*)
	;;
*)
	echo "HostConfig.CapDrop=${caps}, want ALL" >&2
	exit 1
	;;
esac

ok=0
for _ in $(seq 1 40); do
	if curl -fsS "http://127.0.0.1:${MGMT_PORT}/v1/health/ready" >/dev/null 2>&1; then
		ok=1
		break
	fi
	sleep 0.25
done
if [ "${ok}" -ne 1 ]; then
	echo "management ready check failed on 127.0.0.1:${MGMT_PORT}" >&2
	docker inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}}' "${CID}" >&2 || true
	docker compose -p "${PROJECT}" -f "${COMPOSE}" logs >&2 || true
	exit 1
fi

ui_code="$(curl -sS -D /tmp/labsnmp-ui.hdr -o /tmp/labsnmp-ui.body -w '%{http_code}' "http://127.0.0.1:${MGMT_PORT}/" || true)"
if [ "${ui_code}" != "404" ]; then
	echo "GET / status=${ui_code}, want 404 (ui.enabled: false / UIEnabled=false)" >&2
	cat /tmp/labsnmp-ui.hdr >&2 || true
	cat /tmp/labsnmp-ui.body >&2 || true
	exit 1
fi
if ! grep -qi 'content-type:.*application/problem+json' /tmp/labsnmp-ui.hdr; then
	echo "GET / content-type is not application/problem+json" >&2
	cat /tmp/labsnmp-ui.hdr >&2 || true
	exit 1
fi
if ! curl -fsS "http://127.0.0.1:${MGMT_PORT}/v1/health/ready" >/dev/null; then
	echo "GET /v1/health/ready failed after SPA-disabled 404" >&2
	exit 1
fi

if ! docker exec "${CID}" /labsnmp version >/dev/null; then
	echo "non-root exec of /labsnmp version failed" >&2
	exit 1
fi
if ! docker exec "${CID}" /labsnmp healthcheck --url=http://127.0.0.1:8088/v1/health/ready >/dev/null; then
	echo "in-container HTTP ready healthcheck failed" >&2
	exit 1
fi
if docker exec "${CID}" /bin/sh -c true >/dev/null 2>&1; then
	echo "image has a shell at /bin/sh" >&2
	exit 1
fi

SMOKE_TOKEN="$(tr -d '\r\n' < "${TOKEN}")"

unauth="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${MGMT_PORT}/v1/state")"
if [ "${unauth}" != "401" ]; then
	echo "unauthenticated GET /v1/state status=${unauth}, want 401" >&2
	exit 1
fi
unauth_ver="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${MGMT_PORT}/v1/version")"
if [ "${unauth_ver}" != "401" ]; then
	echo "unauthenticated GET /v1/version status=${unauth_ver}, want 401" >&2
	exit 1
fi

version="$(curl -fsS -H "Authorization: Bearer ${SMOKE_TOKEN}" \
	"http://127.0.0.1:${MGMT_PORT}/v1/version")"
if ! printf '%s\n' "${version}" | grep -q 'labsnmp.dev/v1alpha1'; then
	echo "authenticated /v1/version missing schema: ${version}" >&2
	exit 1
fi

if command -v snmpget >/dev/null 2>&1; then
	walk="$(snmpget -v2c -c public -t 2 -r 1 "127.0.0.1:${SNMP_PORT}" 1.3.6.1.2.1.1.1.0 || true)"
	if ! printf '%s\n' "${walk}" | grep -q 'LabSNMP container-smoke'; then
		echo "snmpget missing sysDescr LabSNMP container-smoke: ${walk}" >&2
		exit 1
	fi
else
	echo "skip: snmpget not installed (net-snmp CLI interop)" >&2
fi

echo "container contract ok image=${IMAGE} trap=${TRAP_PORT}/udp"

if [ "${LABSNMP_TEST_NET_BIND:-}" != "1" ]; then
	exit 0
fi

echo "gated NET_BIND_SERVICE smoke"
if ! docker run -d --name "${NAME}-bind" \
	--read-only \
	--user 65532:65532 \
	--cap-drop=ALL \
	--cap-add=NET_BIND_SERVICE \
	--security-opt=no-new-privileges:true \
	--tmpfs /tmp:rw,noexec,nosuid,size=16m \
	-v "${CONFIG}:/etc/labsnmp/config.yaml:ro" \
	-v "${TOKEN}:/etc/labsnmp/token:ro" \
	-v "${COMMUNITY}:/etc/labsnmp/community-public:ro" \
	-p 127.0.0.1::8088/tcp \
	"${IMAGE}" \
	serve --config=/etc/labsnmp/config.yaml --snmp-listen=:161 --trap-listen=:162 --management-listen=:8088; then
	echo "LABSNMP_TEST_NET_BIND=1: runtime could not start with NET_BIND_SERVICE; skip" >&2
	exit 0
fi

bind_mgmt="$(docker port "${NAME}-bind" 8088/tcp | head -n1 | awk -F: '{print $NF}')"
ok=0
for _ in $(seq 1 40); do
	if curl -fsS "http://127.0.0.1:${bind_mgmt}/v1/health/ready" >/dev/null 2>&1; then
		ok=1
		break
	fi
	sleep 0.25
done
if [ "${ok}" -ne 1 ]; then
	echo "NET_BIND_SERVICE :161/:162 ready check failed" >&2
	docker logs "${NAME}-bind" >&2 || true
	exit 1
fi
echo "gated NET_BIND_SERVICE :161/:162 ok"
