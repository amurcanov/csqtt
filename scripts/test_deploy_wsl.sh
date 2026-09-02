#!/bin/bash
set -Eeuo pipefail

workspace="${CSQTT_WORKSPACE:-/path/to/your/csqtt}"
peer_port="${CSQTT_TEST_PEER_PORT:-46900}"
web_port="${CSQTT_TEST_WEB_PORT:-46902}"
ssh_port="${CSQTT_TEST_SSH_PORT:-2222}"
script_source="${workspace}/app/src/main/assets/deploy.sh"
binary_source="${CSQTT_TEST_SERVER_BINARY:-${workspace}/app/src/main/assets/csqtt-linux-amd64}"

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 2; }
[ -x "$binary_source" ] || { echo "missing executable server asset: $binary_source" >&2; exit 2; }
[ -f "$script_source" ] || { echo "missing deploy asset: $script_source" >&2; exit 2; }
command -v systemctl >/dev/null 2>&1 || { echo "systemctl is unavailable" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is unavailable" >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "openssl is unavailable" >&2; exit 2; }

deploy_env=(
    "CSQTT_PEER_PORT=${peer_port}"
    "CSQTT_WEB_PORT=${web_port}"
    "CSQTT_SSH_PORT=${ssh_port}"
    "CSQTT_START_STABILITY_SECONDS=1"
)

prepare_upload() {
    install -m 0755 "$script_source" /tmp/deploy.sh
    install -m 0755 "$binary_source" /tmp/.csqtt-upload-server
    install -m 0600 /dev/null /tmp/.csqtt-upload-web.env
    install -m 0600 /dev/null /tmp/.csqtt-upload-overrides.json
    printf '%s\n' 'CSQTT_WEB_USER=deploy-test' 'CSQTT_WEB_PASS=deploy-test-password' > /tmp/.csqtt-upload-web.env
    printf '%s\n' '{"main_password":"deploy-test-main-password","device_id":"deploy-wsl-matrix"}' > /tmp/.csqtt-upload-overrides.json
    chmod 0600 /tmp/.csqtt-upload-web.env /tmp/.csqtt-upload-overrides.json
}

prepare_tls() {
    mkdir -p /etc/csqtt
    if ! openssl x509 -noout -in /etc/csqtt/web_cert.pem >/dev/null 2>&1 || \
       ! openssl pkey -noout -in /etc/csqtt/web_key.pem >/dev/null 2>&1; then
        rm -f /etc/csqtt/web_cert.pem /etc/csqtt/web_key.pem
        openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
            -subj '/CN=csqtt-wsl-deploy-test' \
            -keyout /etc/csqtt/web_key.pem \
            -out /etc/csqtt/web_cert.pem >/dev/null 2>&1
        chmod 600 /etc/csqtt/web_key.pem
        chmod 644 /etc/csqtt/web_cert.pem
    fi
}

assert_running() {
    local mode="$1" code
    if [ "$mode" = "systemd" ]; then
        systemctl is-active --quiet csqtt
    else
        docker inspect --format '{{.State.Running}}' csqtt | grep -qx true
    fi
    ip link show csqtt1 >/dev/null 2>&1
    ss -H -lun "sport = :${peer_port}" | grep -q .
    code="$(curl -k -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 4 "https://127.0.0.1:${web_port}/" || true)"
    case "$code" in 200|301|302|401) return 0 ;; esac
    code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 4 "http://127.0.0.1:${web_port}/" || true)"
    case "$code" in 200|301|302|401) return 0 ;; esac
    echo "web health check failed: https=${code}" >&2
    return 1
}

deploy() {
    local mode="$1"
    prepare_upload
    env "${deploy_env[@]}" "CSQTT_DEPLOY_MODE=${mode}" bash /tmp/deploy.sh install
    assert_running "$mode"
    echo "PASS ${mode} deploy"
}

panel_cookie=""

panel_login() {
    [ -n "$panel_cookie" ] && rm -f -- "$panel_cookie"
    panel_cookie="$(mktemp)"
    local code
    code="$(curl -k -sS -o /dev/null -w '%{http_code}' -c "$panel_cookie" \
        --connect-timeout 2 --max-time 4 -H 'content-type: application/json' \
        --data '{"user":"deploy-test","pass":"deploy-test-password"}' \
        "https://127.0.0.1:${web_port}/api/login" || true)"
    [ "$code" = "200" ] || { echo "panel login failed: ${code}" >&2; return 1; }
}

panel_settings() {
    curl -k -fsS -b "$panel_cookie" --connect-timeout 2 --max-time 4 \
        "https://127.0.0.1:${web_port}/api/settings"
}

assert_dns() {
    local expected="$1" settings
    settings="$(panel_settings)"
    python3 - "$expected" "$settings" <<'PY'
import json
import sys

expected = sys.argv[1]
settings = json.loads(sys.argv[2])
actual = ','.join(filter(None, [settings.get('dns_primary', ''), settings.get('dns_secondary', '')]))
if actual != expected:
    raise SystemExit(f'DNS mismatch: expected {expected}, got {actual}')
PY
}

set_dns() {
    local payload="$1" code
    code="$(curl -k -sS -o /dev/null -w '%{http_code}' -b "$panel_cookie" \
        --connect-timeout 2 --max-time 4 -H 'content-type: application/json' \
        --data "$payload" "https://127.0.0.1:${web_port}/api/settings" || true)"
    [ "$code" = "200" ] || { echo "panel DNS update failed: ${code}" >&2; return 1; }
}

start_udp_blocker() {
    python3 - "$peer_port" <<'PY' &
import socket
import sys
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", int(sys.argv[1])))
while True:
    time.sleep(60)
PY
    blocker_pid=$!
    for _ in $(seq 1 40); do
        ss -H -lunp "sport = :${peer_port}" 2>/dev/null | grep -q "pid=${blocker_pid}" && return 0
        sleep 0.05
    done
    kill -KILL "$blocker_pid" 2>/dev/null || true
    echo "cannot bind UDP/${peer_port} for the force-release check" >&2
    return 1
}

cleanup() {
    set +e
    env "${deploy_env[@]}" bash /tmp/deploy.sh uninstall >/dev/null 2>&1
    docker rm -f csqtt csqtt-vpn >/dev/null 2>&1
    ip link del csqtt1 >/dev/null 2>&1
    [ -n "$panel_cookie" ] && rm -f -- "$panel_cookie"
    set -e
}

clear_test_state() {
    cleanup
    [ "${CSQTT_TEST_WIPE_STATE:-0}" = "1" ] && rm -rf -- /etc/csqtt
}

trap clear_test_state EXIT
clear_test_state
prepare_tls

deploy systemd
panel_login
assert_dns "77.88.8.8,77.88.8.1"

set_dns '{"dns_provider":"xbox"}'
assert_dns "111.88.96.50,111.88.96.51"
deploy systemd
panel_login
assert_dns "111.88.96.50,111.88.96.51"

set_dns '{"dns_primary":"203.0.113.7","dns_secondary":"198.51.100.9"}'
assert_dns "203.0.113.7,198.51.100.9"
deploy systemd
panel_login
assert_dns "77.88.8.8,77.88.8.1"

set_dns '{"dns_primary":"111.88.96.51","dns_secondary":"203.0.113.7"}'
assert_dns "111.88.96.51,203.0.113.7"
deploy systemd
panel_login
assert_dns "111.88.96.50,111.88.96.51"
echo "PASS DNS deploy migration"

systemctl stop csqtt
for _ in $(seq 1 40); do
    ss -H -lun "sport = :${peer_port}" | grep -q . || break
    sleep 0.1
done
start_udp_blocker
deploy systemd
if kill -0 "$blocker_pid" 2>/dev/null; then
    echo "configured UDP port blocker survived deploy" >&2
    exit 1
fi
echo "PASS force release UDP/${peer_port}"

if [ "${CSQTT_TEST_SKIP_DOCKER:-0}" = "1" ]; then
    echo "PASS systemd-only deploy matrix"
    exit 0
fi

command -v docker >/dev/null 2>&1 || { echo "docker is unavailable" >&2; exit 3; }
docker info >/dev/null
deploy docker
panel_login
assert_dns "111.88.96.50,111.88.96.51"
deploy docker
docker rename csqtt csqtt-vpn
deploy systemd
docker inspect csqtt-vpn >/dev/null 2>&1 && { echo "legacy Docker CSQTT container survived mode switch" >&2; exit 1; }
echo "PASS docker-to-systemd cleanup"

deploy docker
systemctl is-active --quiet csqtt && { echo "legacy systemd CSQTT runtime survived mode switch" >&2; exit 1; }
echo "PASS systemd-to-docker cleanup"
