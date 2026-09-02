#!/bin/bash
set -Eeuo pipefail

workspace="${CSQTT_WORKSPACE:-/path/to/your/csqtt}"
peer_port="${CSQTT_TEST_PEER_PORT:-46910}"
web_port="${CSQTT_TEST_WEB_PORT:-46912}"
ssh_port="${CSQTT_TEST_SSH_PORT:-2224}"
script_source="${workspace}/app/src/main/assets/deploy.sh"
binary_source="${CSQTT_TEST_SERVER_BINARY:-${workspace}/app/src/main/assets/csqtt-linux-amd64}"
action="${1:-start}"
deploy_mode="${CSQTT_TEST_DEPLOY_MODE:-systemd}"

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 2; }

deploy_env=(
    "CSQTT_PEER_PORT=${peer_port}"
    "CSQTT_WEB_PORT=${web_port}"
    "CSQTT_SSH_PORT=${ssh_port}"
    "CSQTT_START_STABILITY_SECONDS=1"
    "CSQTT_DEPLOY_MODE=${deploy_mode}"
)

prepare_tls() {
    mkdir -p /etc/csqtt
    if ! openssl x509 -noout -in /etc/csqtt/web_cert.pem >/dev/null 2>&1 || \
       ! openssl pkey -noout -in /etc/csqtt/web_key.pem >/dev/null 2>&1; then
        rm -f /etc/csqtt/web_cert.pem /etc/csqtt/web_key.pem
        openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
            -subj '/CN=csqtt-wsl-e2e-test' \
            -keyout /etc/csqtt/web_key.pem \
            -out /etc/csqtt/web_cert.pem >/dev/null 2>&1
        chmod 600 /etc/csqtt/web_key.pem
        chmod 644 /etc/csqtt/web_cert.pem
    fi
}

prepare_upload() {
    install -m 0755 "$script_source" /tmp/deploy.sh
    install -m 0755 "$binary_source" /tmp/.csqtt-upload-server
    install -m 0600 /dev/null /tmp/.csqtt-upload-web.env
    install -m 0600 /dev/null /tmp/.csqtt-upload-overrides.json
    printf '%s\n' 'CSQTT_WEB_USER=e2e-test' 'CSQTT_WEB_PASS=e2e-test-password' > /tmp/.csqtt-upload-web.env
    printf '%s\n' '{"main_password":"e2e-local-password-20260830","device_id":"e2e-windows-client"}' > /tmp/.csqtt-upload-overrides.json
    chmod 0600 /tmp/.csqtt-upload-web.env /tmp/.csqtt-upload-overrides.json
}

verify_runtime() {
    case "$deploy_mode" in
        systemd)
            systemctl is-active --quiet csqtt
            ;;
        docker)
            docker inspect --format '{{.State.Running}}' csqtt | grep -qx true
            ;;
        *)
            echo "unsupported deploy mode: $deploy_mode" >&2
            exit 2
            ;;
    esac
    ss -H -lun "sport = :${peer_port}" | grep -q .
    ip link show csqtt1 >/dev/null 2>&1
}

case "$action" in
    start)
        [ -x "$binary_source" ] || { echo "missing executable server asset" >&2; exit 2; }
        [ -f "$script_source" ] || { echo "missing deploy asset" >&2; exit 2; }
        prepare_tls
        prepare_upload
        env "${deploy_env[@]}" bash /tmp/deploy.sh uninstall >/dev/null 2>&1 || true
        prepare_tls
        prepare_upload
        env "${deploy_env[@]}" bash /tmp/deploy.sh install
        verify_runtime
        echo "READY ${peer_port}"
        ;;
    redeploy)
        [ -x "$binary_source" ] || { echo "missing executable server asset" >&2; exit 2; }
        [ -f "$script_source" ] || { echo "missing deploy asset" >&2; exit 2; }
        prepare_tls
        prepare_upload
        env "${deploy_env[@]}" bash /tmp/deploy.sh install
        verify_runtime
        echo "REDEPLOYED ${peer_port}"
        ;;
    stop)
        [ -f /tmp/deploy.sh ] || install -m 0755 "$script_source" /tmp/deploy.sh
        env "${deploy_env[@]}" bash /tmp/deploy.sh uninstall >/dev/null 2>&1 || true
        docker rm -f csqtt csqtt-vpn >/dev/null 2>&1 || true
        ip link del csqtt1 >/dev/null 2>&1 || true
        echo "STOPPED ${peer_port}"
        ;;
    *)
        echo "usage: $0 start|redeploy|stop" >&2
        exit 2
        ;;
esac
