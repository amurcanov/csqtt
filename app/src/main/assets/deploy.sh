#!/bin/bash
# SPDX-FileCopyrightText: 2026 amurcanov
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export TERM="${TERM:-xterm}"

readonly SCRIPT_VERSION="2.1.5"
readonly LOG_FILE="/var/log/csqtt-install.log"
readonly PEER_PORT="${CSQTT_PEER_PORT:-46000}"
readonly SSH_PORT="${CSQTT_SSH_PORT:-22}"
readonly WEB_PORT="${CSQTT_WEB_PORT:-46002}"
readonly LE_HTTP_PORT="80"
readonly LE_RENEW_BEFORE_SECONDS="86400"
readonly DEPLOY_MODE="${CSQTT_DEPLOY_MODE:-systemd}"
readonly CSQTT_IFACE="csqtt1"
readonly CSQTT_CONFIG_DIR="/etc/csqtt"
readonly CSQTT_LE_CERTBOT="/opt/csqtt-certbot/bin/certbot"
readonly CSQTT_LE_VENV="/opt/csqtt-certbot"
readonly CSQTT_LE_STATE_FILE="${CSQTT_CONFIG_DIR}/letsencrypt-ip.env"
readonly CSQTT_LE_RENEW_HELPER="/usr/local/lib/csqtt/letsencrypt-renew.sh"
readonly CSQTT_LE_SERVICE="csqtt-letsencrypt.service"
readonly CSQTT_LE_TIMER="csqtt-letsencrypt.timer"
# Persistent state is intentionally kept on both redeploy and uninstall.  The
# only durable database format is SQLite; its WAL sidecars are part of the
# same consistent state while the process is running.
readonly CSQTT_DATABASE_FILE="csqtt.db"
readonly CSQTT_DATABASE_WAL_FILE="csqtt.db-wal"
readonly CSQTT_DATABASE_SHM_FILE="csqtt.db-shm"
# Legacy JSON is only a one-time migration input. The installer must preserve
# it across cutover; the server removes it only after SQLite import commits.
readonly CSQTT_LEGACY_MIGRATION_JSON="passwords.json"
readonly CSQTT_LEGACY_MIGRATION_IMPORTED_JSON="passwords.json.imported"
readonly CSQTT_ENV_FILE="${CSQTT_CONFIG_DIR}/csqtt.env"
readonly CSQTT_DEPLOY_OVERRIDES_FILE="${CSQTT_CONFIG_DIR}/deploy-overrides.json"
readonly UPLOAD_BINARY="/tmp/.csqtt-upload-server"
readonly UPLOAD_ENV_FILE="/tmp/.csqtt-upload-web.env"
readonly UPLOAD_OVERRIDES_FILE="/tmp/.csqtt-upload-overrides.json"
readonly CSQTT_SYSCTL_FILE="/etc/sysctl.d/99-csqtt.conf"
readonly CSQTT_UDP_SYSCTL_FILE="/etc/sysctl.d/99-csqtt-udp-buffers.conf"
readonly IPT_COMMENT="CSQTT_MANAGED"
readonly CSQTT_DOCKER_IMAGE="csqtt:2.1.5"
readonly CSQTT_DOCKER_CONTAINER="csqtt"
readonly XT_WAIT="${CSQTT_XT_WAIT:-2}"
readonly START_STABILITY_SECONDS="${CSQTT_START_STABILITY_SECONDS:-1}"
readonly EXIT_INVALID_ARGUMENT=2
readonly EXIT_PREFLIGHT_FAILED=20
readonly EXIT_CUTOVER_FAILED=30

SYSTEMD_NEEDS_RELOAD=0
DEPLOY_PHASE="initial"
DOCKER_CONTEXT_DIR=""
CSQTT_DOCKER_CANDIDATE_IMAGE=""

validate_port() {
    local name="$1" value="$2"
    case "$value" in
        ''|*[!0-9]*) die "$name должен быть числом от 1 до 65535, получено: $value" ;;
    esac
    if [ "$value" -lt 1 ] || [ "$value" -gt 65535 ]; then
        die "$name должен быть в диапазоне 1..65535, получено: $value"
    fi
}

C_GREEN=''; C_YELLOW=''; C_RED=''
C_CYAN='';  C_BOLD='';      C_NC=''

log_info()  { echo -e "${C_GREEN}[✓]${C_NC} $*" | tee -a "$LOG_FILE"; }
log_warn()  { echo -e "${C_YELLOW}[!]${C_NC} $*" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${C_RED}[✗]${C_NC} $*" | tee -a "$LOG_FILE"; }
log_step()  { echo -e "${C_CYAN}[►]${C_NC} ${C_BOLD}$*${C_NC}" | tee -a "$LOG_FILE"; }

default_exit_code() {
    case "$DEPLOY_PHASE" in
        validation) printf '%s' "$EXIT_INVALID_ARGUMENT" ;;
        preflight) printf '%s' "$EXIT_PREFLIGHT_FAILED" ;;
        cutover|activation) printf '%s' "$EXIT_CUTOVER_FAILED" ;;
        *) printf '%s' 1 ;;
    esac
}

die() {
    local message="$1" code="${2:-$(default_exit_code)}"
    log_error "$message"
    printf 'CSQTT_DEPLOY_ERROR|%s|%s\n' "$DEPLOY_PHASE" "$message"
    cleanup_deploy_uploads
    exit "$code"
}

prog() { echo "CSQTT_PROGRESS|$1|$2"; }

run_timed() {
    local label="$1" started=$SECONDS
    shift
    "$@"
    log_info "Время этапа «$label»: $((SECONDS - started))с"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "Скрипт должен быть запущен от root. Если sudo отсутствует, зайдите под root и запустите: bash $0 install"
    fi
}

OS_ID="" ; PKG_MGR=""

detect_os() {
    log_step "Определение операционной системы..."
    if [ ! -f /etc/os-release ]; then
        die "Файл /etc/os-release не найден."
    fi
    # Runtime distribution metadata exists on every supported server.
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop)     PKG_MGR="apt" ;;
        centos|rhel|rocky|almalinux|oracle|ol) PKG_MGR="yum"
            command -v dnf &>/dev/null && PKG_MGR="dnf" ;;
        fedora)                          PKG_MGR="dnf" ;;
        arch|manjaro|endeavouros)        PKG_MGR="pacman" ;;
        *)
            case " ${ID_LIKE:-} " in
                *" debian "*) PKG_MGR="apt" ;;
                *" rhel "*|*" fedora "*)
                    PKG_MGR="yum"
                    command -v dnf &>/dev/null && PKG_MGR="dnf"
                    ;;
                *" arch "*) PKG_MGR="pacman" ;;
                *) die "Неподдерживаемый дистрибутив: $OS_ID" ;;
            esac
            ;;
    esac
    log_info "ОС: ${PRETTY_NAME:-$OS_ID} | PM: $PKG_MGR"
}

pkg_update_done=0

pkg_update() {
    [ "$pkg_update_done" = "1" ] && return 0
    log_step "Обновление индексов пакетов..."
    case "$PKG_MGR" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y >>"$LOG_FILE" 2>&1 || log_warn "apt update завершился с ошибкой, пробую продолжить"
            ;;
        dnf)    dnf makecache -y >>"$LOG_FILE" 2>&1 || true ;;
        yum)    yum makecache -y >>"$LOG_FILE" 2>&1 || true ;;
        pacman) : ;;
    esac
    pkg_update_done=1
}

pkg_install() {
    [ "$#" -eq 0 ] && return 0
    case "$PKG_MGR" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get install -y -qq --no-install-recommends "$@" >>"$LOG_FILE" 2>&1
            ;;
        dnf)    dnf install -y "$@" >>"$LOG_FILE" 2>&1 ;;
        yum)    yum install -y "$@" >>"$LOG_FILE" 2>&1 ;;
        pacman) pacman -Syu --noconfirm --needed "$@" >>"$LOG_FILE" 2>&1 ;;
    esac
}

pkg_install_with_refresh() {
    pkg_install "$@" && return 0
    pkg_update
    pkg_install "$@"
}

install_prerequisites() {
    prog 0.10 "Пакеты..."
    log_step "Проверка базовых зависимостей..."

    local ip_package procps_package
    case "$PKG_MGR" in
        apt)     ip_package="iproute2"; procps_package="procps" ;;
        dnf|yum) ip_package="iproute";  procps_package="procps-ng" ;;
        pacman)  ip_package="iproute2"; procps_package="procps-ng" ;;
    esac

    local -a packages=()
    local need_iptables=0
    command -v ip >/dev/null 2>&1 || packages+=("$ip_package")
    command -v curl >/dev/null 2>&1 || packages+=("curl")
    command -v modprobe >/dev/null 2>&1 || packages+=("kmod")
    if ! command -v sysctl >/dev/null 2>&1 || ! command -v pkill >/dev/null 2>&1; then
        packages+=("$procps_package")
    fi
    command -v iptables >/dev/null 2>&1 || need_iptables=1

    if [ "$PKG_MGR" = "pacman" ] && [ "$need_iptables" -eq 1 ]; then
        packages+=("iptables")
        need_iptables=0
    fi

    if [ "${#packages[@]}" -eq 0 ] && [ "$need_iptables" -eq 0 ]; then
        log_info "Все системные зависимости уже установлены — обновление пакетов не требуется"
        return 0
    fi

    pkg_update
    if [ "${#packages[@]}" -gt 0 ]; then
        pkg_install "${packages[@]}" || die "Не удалось установить обязательные пакеты: ${packages[*]}"
    fi

    if [ "$need_iptables" -eq 1 ]; then
        case "$PKG_MGR:$OS_ID" in
            dnf:fedora)
                pkg_install iptables-nft || pkg_install iptables || \
                    die "Не удалось установить iptables/iptables-nft"
                ;;
            dnf:*|yum:*)
                pkg_install iptables || pkg_install iptables-nft || \
                    die "Не удалось установить iptables/iptables-nft"
                ;;
            *)
                pkg_install iptables || die "Не удалось установить обязательный пакет iptables"
                ;;
        esac
    fi
}

require_runtime_tools() {
    command -v ip >/dev/null 2>&1 || die "Команда ip не найдена. Установите iproute2/iproute."
    command -v iptables >/dev/null 2>&1 || die "Команда iptables не найдена. Она обязательна для TUN и NAT."
    command -v sysctl >/dev/null 2>&1 || die "Команда sysctl не найдена. Установите procps/procps-ng."
    command -v pkill >/dev/null 2>&1 || die "Команда pkill не найдена. Установите procps/procps-ng."
    if [ "$DEPLOY_MODE" = "systemd" ]; then
        command -v systemctl >/dev/null 2>&1 || die "systemctl не найден. Для native-установки нужен VPS с systemd."
    fi
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) die "Серверный бинарник CSQTT собран для x86_64; архитектура $(uname -m) пока не поддерживается." ;;
    esac
}

detect_wan_interface() {
    local iface fallback=""
    while IFS= read -r iface; do
        iface="${iface%%@*}"
        [ -n "$iface" ] || continue
        [ -n "$fallback" ] || fallback="$iface"
        if ! is_ignored_wan_interface "$iface" && ip link show "$iface" >/dev/null 2>&1; then
            echo "$iface"
            return 0
        fi
    done <<EOF
$(ip -o -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); break}}')
EOF
    while IFS= read -r iface; do
        iface="${iface%%@*}"
        [ -n "$iface" ] || continue
        [ -n "$fallback" ] || fallback="$iface"
        if ! is_ignored_wan_interface "$iface" && ip link show "$iface" >/dev/null 2>&1; then
            echo "$iface"
            return 0
        fi
    done <<EOF
$(ip -o -4 addr show scope global 2>/dev/null | awk '{sub(/@.*/, "", $2); print $2}')
EOF
    while IFS= read -r iface; do
        iface="${iface%%@*}"
        [ -n "$iface" ] || continue
        [ "$iface" = "lo" ] && continue
        [ -n "$fallback" ] || fallback="$iface"
        if ! is_ignored_wan_interface "$iface" && ip link show "$iface" >/dev/null 2>&1; then
            echo "$iface"
            return 0
        fi
    done <<EOF
$(ls /sys/class/net/ 2>/dev/null || true)
EOF
    [ -n "$fallback" ] && echo "$fallback"
}

is_ignored_wan_interface() {
    local iface="${1%%@*}"
    case "$iface" in
        ""|lo|"$CSQTT_IFACE"|csqtp*|tun*|tap*|wg*|warp*|Warp*|WARP*|CloudflareWARP*|tailscale*|zt*|docker*|br-*|veth*|cni*|flannel*|virbr*|podman*|kube*|dummy*|ifb*)
            return 0
            ;;
    esac
    return 1
}

detect_firewall() {
    command -v iptables >/dev/null 2>&1 || \
        die "iptables не найден: без него сервер не сможет создать рабочий TUN/NAT."
    local ver
    ver="$(iptables --version 2>/dev/null || echo unknown)"
    log_info "Firewall backend: iptables (${ver})"
}

ipt_add_or_ensure() {
    local table="$1" chain="$2"
    shift 2
    local -a targs=()
    [ "$table" = "filter" ] || targs=(-t "$table")
    iptables -w "$XT_WAIT" "${targs[@]}" -C "$chain" "$@" >/dev/null 2>&1 || \
        iptables -w "$XT_WAIT" "${targs[@]}" -I "$chain" 1 "$@" >>"$LOG_FILE" 2>&1
}

fw_add_input_udp() {
    local port="$1"
    ipt_add_or_ensure filter INPUT -p udp --dport "$port" -m comment --comment "$IPT_COMMENT" -j ACCEPT || \
        die "Не удалось открыть ${port}/udp в iptables"
}

fw_add_input_tcp() {
    local port="$1"
    ipt_add_or_ensure filter INPUT -p tcp --dport "$port" -m comment --comment "$IPT_COMMENT" -j ACCEPT || \
        die "Не удалось открыть ${port}/tcp в iptables"
}

fw_add_forward() {
    ipt_add_or_ensure filter INPUT -i "$CSQTT_IFACE" -s "10.66.67.0/24" -m comment --comment "$IPT_COMMENT" -j ACCEPT || \
        die "Не удалось установить INPUT -i $CSQTT_IFACE"
    ipt_add_or_ensure filter FORWARD -i "$CSQTT_IFACE" -m comment --comment "$IPT_COMMENT" -j ACCEPT || \
        die "Не удалось установить FORWARD -i $CSQTT_IFACE"
    ipt_add_or_ensure filter FORWARD -o "$CSQTT_IFACE" -m comment --comment "$IPT_COMMENT" -j ACCEPT || \
        die "Не удалось установить FORWARD -o $CSQTT_IFACE"
}

fw_add_masquerade() {
    local iface="$1" subnet="$2"
    iptables -w "$XT_WAIT" -t nat -C POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$IPT_COMMENT" -j MASQUERADE >/dev/null 2>&1 || \
        iptables -w "$XT_WAIT" -t nat -A POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$IPT_COMMENT" -j MASQUERADE >>"$LOG_FILE" 2>&1 || \
        die "Не удалось установить NAT MASQUERADE через $iface"
}

fw_add_mss_clamping() {
    local subnet="$1"
    ipt_add_or_ensure mangle FORWARD -s "$subnet" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu || \
        die "Не удалось установить исходящий TCP MSS clamping"
    ipt_add_or_ensure mangle FORWARD -d "$subnet" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu || \
        die "Не удалось установить входящий TCP MSS clamping"
}

delete_marked_rules() {
    local table="$1" chain="$2" marker="$3" _ numbers number
    local -a targs=()
    [ "$table" = "filter" ] || targs=(-t "$table")
    for _ in 1 2 3 4 5 6 7 8; do
        numbers="$(iptables -w "$XT_WAIT" "${targs[@]}" -S "$chain" 2>/dev/null | awk -v chain="$chain" -v marker="$marker" '
$1 == "-A" && $2 == chain {
    n++
    if (index($0, marker)) hit[++h] = n
}
END {
    for (i = h; i >= 1; i--) print hit[i]
}
')" || return 0
        [ -n "$numbers" ] || break
        while IFS= read -r number; do
            [ -n "$number" ] && iptables -w "$XT_WAIT" "${targs[@]}" -D "$chain" "$number" >/dev/null 2>&1 || true
        done <<EOF
$numbers
EOF
    done
}

ipt_del_repeat() {
    local table="$1" chain="$2" _
    shift 2
    local -a targs=()
    [ "$table" = "filter" ] || targs=(-t "$table")
    for _ in 1 2 3 4 5 6 7 8; do
        iptables -w "$XT_WAIT" "${targs[@]}" -D "$chain" "$@" >/dev/null 2>&1 || break
    done
}

cleanup_csqtt_netfilter_rules() {
    local table chain marker wan
    for marker in "$IPT_COMMENT" CSQTT_MIRRORED CSQTT_TPROXY CSQTT_LOCAL_SOCKS CSQTT_LOCAL_SOCKS_MARK CSQTT_SOCKS CSQTT_CASCADE_NO_QUIC; do
        for table in filter nat mangle raw; do
            for chain in INPUT FORWARD PREROUTING POSTROUTING OUTPUT; do
                delete_marked_rules "$table" "$chain" "$marker"
            done
        done
    done
    wan="$(detect_wan_interface 2>/dev/null || true)"
    [ -n "$wan" ] && ipt_del_repeat nat POSTROUTING -s 10.66.67.0/24 -o "$wan" -j MASQUERADE
    ipt_del_repeat nat POSTROUTING -s 10.66.67.0/24 ! -o "$CSQTT_IFACE" -j MASQUERADE
    ipt_del_repeat filter FORWARD -s 10.66.67.0/24 -j ACCEPT
    ipt_del_repeat filter FORWARD -d 10.66.67.0/24 -j ACCEPT
    ipt_del_repeat mangle FORWARD -s 10.66.67.0/24 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ipt_del_repeat mangle FORWARD -d 10.66.67.0/24 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

    # Старые native nft-таблицы удаляем параллельно и с коротким лимитом.
    # Это не вызывает дорогой `nft list ruleset`.
    if command -v nft >/dev/null 2>&1; then
        timeout 1 nft delete table ip csqtt >/dev/null 2>&1 &
        local p1=$!
        timeout 1 nft delete table inet csqtt >/dev/null 2>&1 &
        local p2=$!
        timeout 1 nft delete table inet csqtt_mangle >/dev/null 2>&1 &
        local p3=$!
        wait "$p1" 2>/dev/null || true
        wait "$p2" 2>/dev/null || true
        wait "$p3" 2>/dev/null || true
    fi
}

cleanup_csqtt_proxy_policy() {
    local _
    for _ in 1 2 3 4; do ip -4 rule del fwmark 0x7531/0x7531 priority 30001 table 30001 >/dev/null 2>&1 || break; done
    for _ in 1 2 3 4; do ip -4 rule del fwmark 0x422 priority 1066 table 1066 >/dev/null 2>&1 || break; done
    for _ in 1 2 3 4; do ip -4 rule del from 10.66.67.0/24 priority 1066 table 1066 >/dev/null 2>&1 || break; done
    ip -4 route flush table 30001 >/dev/null 2>&1 || true
    ip -4 route flush table 1066 >/dev/null 2>&1 || true
    ip -4 route flush cache >/dev/null 2>&1 || true
}

secure_persistent_state() {
    [ -d "$CSQTT_CONFIG_DIR" ] || return 0
    chmod 700 "$CSQTT_CONFIG_DIR" 2>/dev/null || true

    # Never use a blanket find/rm here. SQLite in WAL mode consists of the
    # main database and up to two sidecars; legacy JSON must also survive until
    # the new server commits its SQLite import.
    local file
    for file in \
        "$CSQTT_DATABASE_FILE" \
        "$CSQTT_DATABASE_WAL_FILE" \
        "$CSQTT_DATABASE_SHM_FILE" \
        "$CSQTT_LEGACY_MIGRATION_JSON" \
        "$CSQTT_LEGACY_MIGRATION_IMPORTED_JSON"; do
        [ -f "$CSQTT_CONFIG_DIR/$file" ] && chmod 600 "$CSQTT_CONFIG_DIR/$file" 2>/dev/null || true
    done
    [ -f "$CSQTT_ENV_FILE" ] && chmod 600 "$CSQTT_ENV_FILE" 2>/dev/null || true
    [ -f "$CSQTT_DEPLOY_OVERRIDES_FILE" ] && chmod 600 "$CSQTT_DEPLOY_OVERRIDES_FILE" 2>/dev/null || true
    [ -f "$CSQTT_CONFIG_DIR/web_cert.pem" ] && chmod 644 "$CSQTT_CONFIG_DIR/web_cert.pem" 2>/dev/null || true
    [ -f "$CSQTT_CONFIG_DIR/web_key.pem" ] && chmod 600 "$CSQTT_CONFIG_DIR/web_key.pem" 2>/dev/null || true
    [ -f "$CSQTT_LE_STATE_FILE" ] && chmod 600 "$CSQTT_LE_STATE_FILE" 2>/dev/null || true
}

clear_runtime_config_preserving_database() {
    local entry base
    mkdir -p "$CSQTT_CONFIG_DIR" || die "Не удалось подготовить каталог конфигурации"
    shopt -s nullglob dotglob
    for entry in "$CSQTT_CONFIG_DIR"/*; do
        base="${entry##*/}"
        case "$base" in
            "$CSQTT_DATABASE_FILE"|"$CSQTT_DATABASE_WAL_FILE"|"$CSQTT_DATABASE_SHM_FILE"|"$CSQTT_LEGACY_MIGRATION_JSON"|"$CSQTT_LEGACY_MIGRATION_IMPORTED_JSON"|web_cert.pem|web_key.pem|letsencrypt-ip.env) continue ;;
        esac
        rm -rf -- "$entry"
    done
    shopt -u nullglob dotglob
    secure_persistent_state
}

remove_managed_work_dir() {
    local path="$1"
    case "$path" in
        /tmp/csqtt-docker.*)
            rm -rf -- "$path"
            ;;
        "")
            ;;
        *)
            log_warn "Отказ от удаления неожиданного временного пути: $path"
            return 1
            ;;
    esac
}

cleanup_deploy_uploads() {
    local docker_context="$DOCKER_CONTEXT_DIR"
    DOCKER_CONTEXT_DIR=""
    remove_managed_work_dir "$docker_context" || true
    rm -f -- "$UPLOAD_BINARY" "$UPLOAD_ENV_FILE" "$UPLOAD_OVERRIDES_FILE"
}

validate_candidate_environment() {
    local candidate_env="$1" candidate_overrides="$2"
    grep -Eq '^[[:space:]]*(export[[:space:]]+)?CSQTT_WEB_USER=.+$' "$candidate_env" || \
        die "В переданной WEB-конфигурации отсутствует CSQTT_WEB_USER" "$EXIT_PREFLIGHT_FAILED"
    grep -Eq '^[[:space:]]*(export[[:space:]]+)?CSQTT_WEB_PASS=.+$' "$candidate_env" || \
        die "В переданной WEB-конфигурации отсутствует CSQTT_WEB_PASS" "$EXIT_PREFLIGHT_FAILED"
    grep -q '"main_password"' "$candidate_overrides" || \
        die "В deploy-конфигурации отсутствует main_password" "$EXIT_PREFLIGHT_FAILED"
    grep -q '"device_id"' "$candidate_overrides" || \
        die "В deploy-конфигурации отсутствует device_id" "$EXIT_PREFLIGHT_FAILED"
}

prepare_uploaded_release() {
    DEPLOY_PHASE="preflight"
    [ -f "$UPLOAD_BINARY" ] && [ -s "$UPLOAD_BINARY" ] || \
        die "Новый бинарник не загружен или пуст" "$EXIT_PREFLIGHT_FAILED"
    [ -f "$UPLOAD_ENV_FILE" ] && [ -s "$UPLOAD_ENV_FILE" ] || \
        die "Одноразовая WEB-конфигурация не загружена" "$EXIT_PREFLIGHT_FAILED"
    [ -f "$UPLOAD_OVERRIDES_FILE" ] && [ -s "$UPLOAD_OVERRIDES_FILE" ] || \
        die "Одноразовая deploy-конфигурация не загружена" "$EXIT_PREFLIGHT_FAILED"

    chmod 0755 "$UPLOAD_BINARY" || die "Не удалось подготовить загруженный бинарник csqtt" "$EXIT_PREFLIGHT_FAILED"
    chmod 0600 "$UPLOAD_ENV_FILE" "$UPLOAD_OVERRIDES_FILE" || \
        die "Не удалось защитить загруженную конфигурацию" "$EXIT_PREFLIGHT_FAILED"
    validate_candidate_environment "$UPLOAD_ENV_FILE" "$UPLOAD_OVERRIDES_FILE"
    log_info "Загруженный бинарник и конфигурация проверены до остановки текущего сервиса"
}

finish_deployment() {
    if command -v docker >/dev/null 2>&1 && [ -n "$CSQTT_DOCKER_CANDIDATE_IMAGE" ]; then
        docker image rm "$CSQTT_DOCKER_CANDIDATE_IMAGE" >/dev/null 2>&1 || \
            log_warn "Не удалось снять временный Docker tag $CSQTT_DOCKER_CANDIDATE_IMAGE"
    fi
    cleanup_deploy_uploads
}

# Удаляет TUN-интерфейсы csqtp*, оставшиеся от старой tun2proxy-архитектуры
# локального SOCKS5-форвардера (новые версии используют TPROXY без второго TUN).
cleanup_legacy_proxy_interfaces() {
    local iface
    for iface in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep '^csqtp' || true); do
        timeout 2 ip link del "$iface" 2>/dev/null || true
    done
}

csqtt_cleanup() {
    prog 0.15 "Очистка..."
    echo "🧹 Переключение со старой установки CSQTT..."

    local had_old_install=0
    if [ -e /etc/systemd/system/csqtt.service ] || [ -x /usr/local/bin/csqtt ] || \
       [ -d "$CSQTT_CONFIG_DIR" ] || ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
        had_old_install=1
    fi

    if command -v docker >/dev/null 2>&1 && docker inspect "$CSQTT_DOCKER_CONTAINER" >/dev/null 2>&1; then
        timeout 10 docker rm -f "$CSQTT_DOCKER_CONTAINER" >/dev/null 2>&1 || \
            die "Не удалось остановить старый Docker-контейнер"
    fi

    # После успешного preflight останавливаем writer до копирования SQLite.
    # Если обычная остановка зависла, используем ограниченный fallback, а не
    # продолжаем с потенциально активным процессом базы данных.
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$CSQTT_LE_TIMER" --no-block >/dev/null 2>&1 || true
        timeout 10 systemctl stop "$CSQTT_LE_SERVICE" >/dev/null 2>&1 || true
        timeout 10 systemctl stop csqtt >/dev/null 2>&1 || true
        if systemctl is-active --quiet csqtt; then
            timeout 2 systemctl kill --kill-who=all --signal=SIGKILL csqtt >/dev/null 2>&1 || true
        fi
    fi
    if pgrep -x csqtt >/dev/null 2>&1; then
        pkill -TERM -x csqtt >/dev/null 2>&1 || true
        sleep 1
        pgrep -x csqtt >/dev/null 2>&1 && pkill -KILL -x csqtt >/dev/null 2>&1 || true
    fi
    pgrep -x csqtt >/dev/null 2>&1 && die "Старый процесс csqtt не остановлен; переключение отменено"

    [ -e /etc/systemd/system/csqtt.service ] || [ -L /etc/systemd/system/csqtt.service ] && SYSTEMD_NEEDS_RELOAD=1
    [ -d /etc/systemd/system/csqtt.service.d ] && SYSTEMD_NEEDS_RELOAD=1
    rm -f /etc/systemd/system/csqtt.service
    rm -rf /etc/systemd/system/csqtt.service.d
    rm -f /etc/systemd/system/multi-user.target.wants/csqtt.service
    rm -f /usr/local/bin/csqtt
    rm -rf /usr/local/lib/csqtt
    clear_runtime_config_preserving_database

    if ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
        timeout 2 ip link del "$CSQTT_IFACE" 2>/dev/null || true
    fi
    cleanup_legacy_proxy_interfaces

    cleanup_csqtt_proxy_policy || true
    if [ "$had_old_install" -eq 1 ]; then
        cleanup_csqtt_netfilter_rules || true
    fi

    echo "✓ Старый runtime удалён; SQLite/legacy JSON state сохранён"
}

setup_sysctl() {
    prog 0.25 "Sysctl..."
    echo "⚙️  Настройка сетевых параметров..."

    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    mkdir -p /etc/sysctl.d
    cat > "$CSQTT_SYSCTL_FILE" << 'SYSEOF'
net.ipv4.ip_forward = 1
# TCP BBR (Bottleneck Bandwidth and Round-trip propagation time)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Max connection tracking (for TPROXY & heavy load)
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200

# Socket limits
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_tw_reuse = 1
SYSEOF

    cat > "$CSQTT_UDP_SYSCTL_FILE" << 'SYSEOF'
# Extreme buffer sizes for 100-200+ Mbps proxying
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# Auto-tuning TCP buffers
net.ipv4.tcp_rmem = 4096 1048576 33554432
net.ipv4.tcp_wmem = 4096 1048576 33554432

# Enable Window Scaling
net.ipv4.tcp_window_scaling = 1
SYSEOF

    sysctl -p "$CSQTT_SYSCTL_FILE" >>"$LOG_FILE" 2>&1 || log_warn "Не удалось применить некоторые параметры BBR/sysctl (возможно ядро не поддерживает BBR)"
    sysctl -p "$CSQTT_UDP_SYSCTL_FILE" >>"$LOG_FILE" 2>&1 || log_warn "Ядро ограничило UDP/TCP буферы; сервер продолжит работу с доступными значениями"

    [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ] || \
        die "IPv4 forwarding невозможно включить на этом VPS"

    echo "✓ Sysctl настроен"
}

setup_nat_and_firewall() {
    prog 0.40 "NAT + Firewall..."
    echo "🛡  Настройка NAT и фаервола..."

    local iface
    iface=$(detect_wan_interface)

    if [ -z "$iface" ]; then
        die "Не удалось определить WAN-интерфейс для NAT подсети 10.66.67.0/24"
    fi
    ip link show "$iface" >/dev/null 2>&1 || die "Определённый WAN-интерфейс $iface не существует"

    log_info "WAN-интерфейс: $iface"

    fw_add_input_udp "$PEER_PORT"
    fw_add_input_tcp "$SSH_PORT"
    fw_add_input_tcp "$WEB_PORT"
    fw_add_input_tcp "$LE_HTTP_PORT"

    fw_add_forward

    fw_add_masquerade "$iface" "10.66.67.0/24"
    
    fw_add_mss_clamping "10.66.67.0/24"

    echo "✓ NAT: MASQUERADE на $iface для 10.66.67.0/24"
    echo "✓ Порты: ${PEER_PORT}/udp(PEER), ${SSH_PORT}/tcp(SSH), ${WEB_PORT}/tcp(WEB), ${LE_HTTP_PORT}/tcp(LE)"
    echo "✓ TCP MSS Clamping включен"
}

write_network_helper() {
    local target="$1"
    cat > "$target" << NETEOF
#!/bin/sh
set -eu
    PEER_PORT="$PEER_PORT"
SSH_PORT="$SSH_PORT"
WEB_PORT="$WEB_PORT"
LE_HTTP_PORT="$LE_HTTP_PORT"
CSQTT_IFACE="$CSQTT_IFACE"
IPT_COMMENT="$IPT_COMMENT"
SUBNET="10.66.67.0/24"
XT_WAIT="$XT_WAIT"

command -v ip >/dev/null 2>&1 || exit 20
command -v iptables >/dev/null 2>&1 || exit 21
[ -w /proc/sys/net/ipv4/ip_forward ] && echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

is_ignored_wan_interface() {
    ignored_iface="\${1%%@*}"
    case "\$ignored_iface" in
        ""|lo|"\$CSQTT_IFACE"|csqtp*|tun*|tap*|wg*|warp*|Warp*|WARP*|CloudflareWARP*|tailscale*|zt*|docker*|br-*|veth*|cni*|flannel*|virbr*|podman*|kube*|dummy*|ifb*)
            return 0
            ;;
    esac
    return 1
}

detect_wan_interface() {
    fallback=""
    for iface in \$(ip -o -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if(\$i=="dev") {print \$(i+1); break}}'); do
        iface="\${iface%%@*}"
        [ -n "\$iface" ] || continue
        [ -n "\$fallback" ] || fallback="\$iface"
        if ! is_ignored_wan_interface "\$iface" && ip link show "\$iface" >/dev/null 2>&1; then
            echo "\$iface"
            return 0
        fi
    done
    for iface in \$(ip -o -4 addr show scope global 2>/dev/null | awk '{sub(/@.*/, "", \$2); print \$2}'); do
        iface="\${iface%%@*}"
        [ -n "\$iface" ] || continue
        [ -n "\$fallback" ] || fallback="\$iface"
        if ! is_ignored_wan_interface "\$iface" && ip link show "\$iface" >/dev/null 2>&1; then
            echo "\$iface"
            return 0
        fi
    done
    for iface in \$(ls /sys/class/net/ 2>/dev/null || true); do
        iface="\${iface%%@*}"
        [ -n "\$iface" ] || continue
        [ "\$iface" = "lo" ] && continue
        [ -n "\$fallback" ] || fallback="\$iface"
        if ! is_ignored_wan_interface "\$iface" && ip link show "\$iface" >/dev/null 2>&1; then
            echo "\$iface"
            return 0
        fi
    done
    [ -n "\$fallback" ] && echo "\$fallback"
}

WAN_IFACE=\$(detect_wan_interface)
[ -n "\$WAN_IFACE" ] || exit 22

ipt() { iptables -w "\$XT_WAIT" "\$@"; }
ipt -C INPUT -p udp --dport "\$PEER_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I INPUT -p udp --dport "\$PEER_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C INPUT -p tcp --dport "\$SSH_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I INPUT -p tcp --dport "\$SSH_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C INPUT -p tcp --dport "\$WEB_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I INPUT -p tcp --dport "\$WEB_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C INPUT -p tcp --dport "\$LE_HTTP_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I INPUT -p tcp --dport "\$LE_HTTP_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C INPUT -i "\$CSQTT_IFACE" -s "\$SUBNET" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I INPUT -i "\$CSQTT_IFACE" -s "\$SUBNET" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C FORWARD -i "\$CSQTT_IFACE" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I FORWARD -i "\$CSQTT_IFACE" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C FORWARD -o "\$CSQTT_IFACE" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I FORWARD -o "\$CSQTT_IFACE" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -t nat -C POSTROUTING -s "\$SUBNET" -o "\$WAN_IFACE" -m comment --comment "\$IPT_COMMENT" -j MASQUERADE 2>/dev/null || ipt -t nat -A POSTROUTING -s "\$SUBNET" -o "\$WAN_IFACE" -m comment --comment "\$IPT_COMMENT" -j MASQUERADE
ipt -t mangle -C FORWARD -s "\$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "\$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ipt -t mangle -I FORWARD -s "\$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "\$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu
ipt -t mangle -C FORWARD -d "\$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "\$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ipt -t mangle -I FORWARD -d "\$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "\$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu
NETEOF
    chmod 0755 "$target"
}

install_network_helper() {
    mkdir -p /usr/local/lib/csqtt
    write_network_helper /usr/local/lib/csqtt/network-up.sh
}

verify_configured_network() {
    # Быстрая финальная проверка без повторных семи iptables -C вызовов.
    local iface="${1:-$(detect_wan_interface)}"
    [ -n "$iface" ] || die "WAN-интерфейс не определён при проверке сети"
    [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ] || die "IPv4 forwarding не включён"
    ip link show "$iface" >/dev/null 2>&1 || die "WAN-интерфейс $iface исчез"
}

setup_csqtt_binary() {
    prog 0.60 "Бинарник..."
    echo "Установка csqtt..."

    install -m 0755 "$UPLOAD_BINARY" /usr/local/bin/csqtt || \
        die "Не удалось установить новый бинарник csqtt"
    echo "✓ csqtt установлен"

    # Локальный SOCKS5-форвардер встроен в csqtt (TPROXY + kernel TCP, in-process)
    # и поднимается автоматически при активации SOCKS5-профиля.
    # Удаляем старые внешние копии HEV, если они остались от прошлых версий.
    rm -f /usr/local/bin/hev-socks5-tunnel
    echo "✓ SOCKS5-форвардер встроен в csqtt (TPROXY, поднимается при первом использовании)"

    # Миграция: удаляем старый межсерверный каскад. HEV tunnel остаётся и
    # теперь подключается только к обычному локальному SOCKS5 в 3x-ui.
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop csqtt-cascade.service --no-block >/dev/null 2>&1 || true
        timeout 1 systemctl kill --kill-who=all --signal=SIGKILL csqtt-cascade.service >/dev/null 2>&1 || true
    fi
    if [ -e /etc/systemd/system/csqtt-cascade.service ] || [ -L /etc/systemd/system/csqtt-cascade.service ]; then
        SYSTEMD_NEEDS_RELOAD=1
    fi
    rm -f /etc/systemd/system/csqtt-cascade.service
    rm -f /etc/systemd/system/multi-user.target.wants/csqtt-cascade.service
    rm -f /usr/local/bin/csqtt-cascade /usr/local/bin/hev-socks5-server
    rm -f /usr/local/share/csqtt/cascade.sh
    # Keep the retired cascade configuration for an explicit uninstall or
    # manual migration; a normal redeploy must not erase user configuration.

    mkdir -p "$CSQTT_CONFIG_DIR"
}

setup_csqtt_environment() {
    if [ -s "${CSQTT_CONFIG_DIR}/${CSQTT_DATABASE_FILE}" ]; then
        sed -E -i 's/("dns"[[:space:]]*:[[:space:]]*)"[^"]*"/\1""/' "$UPLOAD_OVERRIDES_FILE" || \
            die "Не удалось сохранить DNS из существующей SQLite-конфигурации"
    fi
    install -m 0600 "$UPLOAD_ENV_FILE" "$CSQTT_ENV_FILE" || \
        die "Не удалось активировать загруженную WEB-конфигурацию"
    install -m 0600 "$UPLOAD_OVERRIDES_FILE" "$CSQTT_DEPLOY_OVERRIDES_FILE" || \
        die "Не удалось активировать загруженную deploy-конфигурацию"
    echo "✓ Конфигурация запуска установлена безопасным EnvironmentFile"
}

LE_CERTBOT_COMMAND=""

is_public_ipv4() {
    local ip="$1" first second third fourth value
    case "$ip" in
        *[!0-9.]*|*..*|.*|*.) return 1 ;;
    esac
    IFS=. read -r first second third fourth <<< "$ip"
    for value in "$first" "$second" "$third" "$fourth"; do
        case "$value" in
            ''|*[!0-9]*) return 1 ;;
        esac
        [ "$value" -le 255 ] || return 1
    done
    [ "$first" -gt 0 ] || return 1
    [ "$first" -lt 224 ] || return 1
    [ "$first" -ne 10 ] || return 1
    [ "$first" -ne 127 ] || return 1
    [ "$first" -ne 0 ] || return 1
    [ "$first" -ne 169 ] || [ "$second" -ne 254 ] || return 1
    [ "$first" -ne 192 ] || [ "$second" -ne 168 ] || return 1
    [ "$first" -ne 172 ] || [ "$second" -lt 16 ] || [ "$second" -gt 31 ] || return 1
    [ "$first" -ne 100 ] || [ "$second" -lt 64 ] || [ "$second" -gt 127 ] || return 1
    [ "$first" -ne 198 ] || [ "$second" -ne 18 ] || return 1
    [ "$first" -ne 198 ] || [ "$second" -ne 19 ] || return 1
    return 0
}

detect_public_ipv4() {
    local endpoint value
    for endpoint in https://api.ipify.org https://ipv4.icanhazip.com; do
        value="$(curl -4 -fsS --connect-timeout 3 --max-time 7 "$endpoint" 2>/dev/null || true)"
        value="$(printf '%s' "$value" | tr -d '[:space:]')"
        if is_public_ipv4 "$value"; then
            printf '%s\n' "$value"
            return 0
        fi
    done
    return 1
}

certbot_supports_ip_certificates() {
    "$1" certonly --help all 2>&1 | grep -Fq -- "--ip-address"
}

ensure_letsencrypt_client() {
    local system_certbot=""
    local -a python_packages=()
    if command -v certbot >/dev/null 2>&1; then
        system_certbot="$(command -v certbot)"
        if certbot_supports_ip_certificates "$system_certbot"; then
            LE_CERTBOT_COMMAND="$system_certbot"
            return 0
        fi
    fi
    if [ -x "$CSQTT_LE_CERTBOT" ] && certbot_supports_ip_certificates "$CSQTT_LE_CERTBOT"; then
        LE_CERTBOT_COMMAND="$CSQTT_LE_CERTBOT"
        return 0
    fi

    log_step "Подготовка Let’s Encrypt клиента..."
    if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
        case "$PKG_MGR" in
            apt) python_packages=(python3 python3-venv) ;;
            dnf|yum) python_packages=(python3 python3-pip) ;;
            pacman) python_packages=(python) ;;
        esac
        if ! pkg_install_with_refresh "${python_packages[@]}"; then
            log_warn "Python/venv недоступны; WEB-панель временно останется на self-signed TLS"
            return 1
        fi
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        if ! pkg_install_with_refresh openssl; then
            log_warn "OpenSSL недоступен; проверка и обновление Let’s Encrypt сертификата отложены"
            return 1
        fi
    fi
    if [ ! -x "$CSQTT_LE_CERTBOT" ]; then
        rm -rf "$CSQTT_LE_VENV"
        if ! python3 -m venv "$CSQTT_LE_VENV" >>"$LOG_FILE" 2>&1; then
            log_warn "Не удалось создать изолированный Let’s Encrypt client; WEB-панель временно останется на self-signed TLS"
            return 1
        fi
    fi
    if ! timeout 180 "$CSQTT_LE_VENV/bin/pip" install --disable-pip-version-check --no-cache-dir --upgrade 'certbot>=5.4,<6' >>"$LOG_FILE" 2>&1; then
        log_warn "Не удалось установить актуальный Certbot с поддержкой IP-сертификатов; WEB-панель временно останется на self-signed TLS"
        return 1
    fi
    if ! certbot_supports_ip_certificates "$CSQTT_LE_CERTBOT"; then
        log_warn "Установленный Certbot не поддерживает Let’s Encrypt IP-сертификаты"
        return 1
    fi
    LE_CERTBOT_COMMAND="$CSQTT_LE_CERTBOT"
    return 0
}

letsencrypt_cert_name() {
    printf 'csqtt-ip-%s\n' "${1//./-}"
}

state_value() {
    local key="$1"
    [ -f "$CSQTT_LE_STATE_FILE" ] || return 1
    sed -n "s/^${key}=//p" "$CSQTT_LE_STATE_FILE" | head -n 1
}

certificate_is_csqtt_rcgen() {
    local issuer subject
    [ -s "$CSQTT_CONFIG_DIR/web_cert.pem" ] || return 1
    command -v openssl >/dev/null 2>&1 || return 1
    issuer="$(openssl x509 -noout -issuer -nameopt RFC2253 -in "$CSQTT_CONFIG_DIR/web_cert.pem" 2>/dev/null || true)"
    subject="$(openssl x509 -noout -subject -nameopt RFC2253 -in "$CSQTT_CONFIG_DIR/web_cert.pem" 2>/dev/null || true)"
    issuer="${issuer#issuer=}"
    subject="${subject#subject=}"
    [ "$subject" = "CN=rcgen self signed cert" ] && [ "$issuer" = "$subject" ]
}

certificate_is_csqtt_letsencrypt() {
    local saved_ip cert_name issuer subject_alt_names
    [ -s "$CSQTT_CONFIG_DIR/web_cert.pem" ] || return 1
    [ -s "$CSQTT_CONFIG_DIR/web_key.pem" ] || return 1
    command -v openssl >/dev/null 2>&1 || return 1
    saved_ip="$(state_value IP 2>/dev/null || true)"
    cert_name="$(state_value CERT_NAME 2>/dev/null || true)"
    is_public_ipv4 "$saved_ip" || return 1
    [ "$cert_name" = "$(letsencrypt_cert_name "$saved_ip")" ] || return 1
    issuer="$(openssl x509 -noout -issuer -nameopt RFC2253 -in "$CSQTT_CONFIG_DIR/web_cert.pem" 2>/dev/null || true)"
    issuer="${issuer#issuer=}"
    case "$issuer" in
        *"O=Let's Encrypt"*) ;;
        *) return 1 ;;
    esac
    subject_alt_names="$(openssl x509 -noout -ext subjectAltName -in "$CSQTT_CONFIG_DIR/web_cert.pem" 2>/dev/null || true)"
    printf '%s\n' "$subject_alt_names" | grep -Fq "IP Address:${saved_ip}"
}

web_certificate_is_csqtt_managed() {
    certificate_is_csqtt_rcgen || certificate_is_csqtt_letsencrypt
}

web_certificate_is_user_managed() {
    [ -s "$CSQTT_CONFIG_DIR/web_cert.pem" ] || return 1
    ! web_certificate_is_csqtt_managed
}

letsencrypt_certificate_is_current() {
    local public_ip="$1" saved_ip
    certificate_is_csqtt_letsencrypt || return 1
    saved_ip="$(state_value IP 2>/dev/null || true)"
    [ "$saved_ip" = "$public_ip" ] || return 1
    [ -s "$CSQTT_CONFIG_DIR/web_cert.pem" ] || return 1
    openssl x509 -noout -checkend "$LE_RENEW_BEFORE_SECONDS" -in "$CSQTT_CONFIG_DIR/web_cert.pem" >/dev/null 2>&1
}

disable_letsencrypt_renewal_timer() {
    command -v systemctl >/dev/null 2>&1 || return 0
    systemctl disable --now "$CSQTT_LE_TIMER" >/dev/null 2>&1 || true
}

install_letsencrypt_certificate() {
    local public_ip="$1" cert_name="$2" source_dir cert_tmp key_tmp state_tmp
    source_dir="/etc/letsencrypt/live/${cert_name}"
    [ -s "$source_dir/fullchain.pem" ] && [ -s "$source_dir/privkey.pem" ] || return 1
    cert_tmp="$(mktemp "${CSQTT_CONFIG_DIR}/.web_cert.XXXXXX")" || return 1
    key_tmp="$(mktemp "${CSQTT_CONFIG_DIR}/.web_key.XXXXXX")" || {
        rm -f -- "$cert_tmp"
        return 1
    }
    state_tmp="$(mktemp "${CSQTT_CONFIG_DIR}/.letsencrypt-ip.XXXXXX")" || {
        rm -f -- "$cert_tmp" "$key_tmp"
        return 1
    }
    if ! install -m 0644 "$source_dir/fullchain.pem" "$cert_tmp" || \
       ! install -m 0600 "$source_dir/privkey.pem" "$key_tmp"; then
        rm -f -- "$cert_tmp" "$key_tmp" "$state_tmp"
        return 1
    fi
    printf 'IP=%s\nCERT_NAME=%s\n' "$public_ip" "$cert_name" > "$state_tmp"
    chmod 0600 "$state_tmp"
    mv -f -- "$cert_tmp" "$CSQTT_CONFIG_DIR/web_cert.pem"
    mv -f -- "$key_tmp" "$CSQTT_CONFIG_DIR/web_key.pem"
    mv -f -- "$state_tmp" "$CSQTT_LE_STATE_FILE"
    secure_persistent_state
}

issue_letsencrypt_ip_certificate() {
    local certbot="$1" public_ip="$2" cert_name="$3"
    if ss -ltnH "sport = :${LE_HTTP_PORT}" 2>/dev/null | grep -q .; then
        log_warn "TCP/${LE_HTTP_PORT} уже занят другим сервисом; Let’s Encrypt IP-сертификат отложен, сохранён self-signed fallback"
        return 1
    fi
    if ! timeout 90 "$certbot" certonly --standalone --http-01-port "$LE_HTTP_PORT" \
        --non-interactive --agree-tos --register-unsafely-without-email \
        --preferred-profile shortlived --ip-address "$public_ip" \
        --cert-name "$cert_name" --keep-until-expiring >>"$LOG_FILE" 2>&1; then
        log_warn "Let’s Encrypt не подтвердил IP ${public_ip}; сохранён self-signed fallback, следующая проверка выполнится автоматически"
        return 1
    fi
    if ! install_letsencrypt_certificate "$public_ip" "$cert_name"; then
        log_warn "Let’s Encrypt выдал сертификат, но CSQTT не смог безопасно активировать его"
        return 1
    fi
    log_info "Let’s Encrypt IP-сертификат активирован для ${public_ip}"
}

write_letsencrypt_renewal_helper() {
    mkdir -p /usr/local/lib/csqtt
    cat > "$CSQTT_LE_RENEW_HELPER" << 'LEHELPER'
#!/bin/bash
set -Eeuo pipefail

CERTBOT="${CSQTT_LE_CERTBOT:-/opt/csqtt-certbot/bin/certbot}"
CONFIG_DIR="${CSQTT_CONFIG_DIR:-/etc/csqtt}"
STATE_FILE="${CONFIG_DIR}/letsencrypt-ip.env"
CERT_PATH="${CONFIG_DIR}/web_cert.pem"
KEY_PATH="${CONFIG_DIR}/web_key.pem"
RENEW_BEFORE_SECONDS="${CSQTT_LE_RENEW_BEFORE_SECONDS:-86400}"
HTTP_PORT="${CSQTT_LE_HTTP_PORT:-80}"
SERVICE_MANAGER="${CSQTT_DEPLOY_MODE:-systemd}"

log() {
    logger -t csqtt-letsencrypt -- "$*" 2>/dev/null || true
    printf '%s\n' "$*"
}

is_public_ipv4() {
    local ip="$1" first second third fourth value
    case "$ip" in
        *[!0-9.]*|*..*|.*|*.) return 1 ;;
    esac
    IFS=. read -r first second third fourth <<< "$ip"
    for value in "$first" "$second" "$third" "$fourth"; do
        case "$value" in
            ''|*[!0-9]*) return 1 ;;
        esac
        [ "$value" -le 255 ] || return 1
    done
    [ "$first" -gt 0 ] && [ "$first" -lt 224 ] && [ "$first" -ne 10 ] && [ "$first" -ne 127 ] || return 1
    [ "$first" -ne 169 ] || [ "$second" -ne 254 ] || return 1
    [ "$first" -ne 192 ] || [ "$second" -ne 168 ] || return 1
    [ "$first" -ne 172 ] || [ "$second" -lt 16 ] || [ "$second" -gt 31 ] || return 1
    [ "$first" -ne 100 ] || [ "$second" -lt 64 ] || [ "$second" -gt 127 ] || return 1
    [ "$first" -ne 198 ] || [ "$second" -ne 18 ] || return 1
    [ "$first" -ne 198 ] || [ "$second" -ne 19 ] || return 1
}

public_ipv4() {
    local endpoint value
    for endpoint in https://api.ipify.org https://ipv4.icanhazip.com; do
        value="$(curl -4 -fsS --connect-timeout 3 --max-time 7 "$endpoint" 2>/dev/null || true)"
        value="$(printf '%s' "$value" | tr -d '[:space:]')"
        if is_public_ipv4 "$value"; then
            printf '%s\n' "$value"
            return 0
        fi
    done
    return 1
}

state_value() {
    local key="$1"
    [ -f "$STATE_FILE" ] || return 1
    sed -n "s/^${key}=//p" "$STATE_FILE" | head -n 1
}

certificate_is_csqtt_rcgen() {
    local issuer subject
    [ -s "$CERT_PATH" ] || return 1
    command -v openssl >/dev/null 2>&1 || return 1
    issuer="$(openssl x509 -noout -issuer -nameopt RFC2253 -in "$CERT_PATH" 2>/dev/null || true)"
    subject="$(openssl x509 -noout -subject -nameopt RFC2253 -in "$CERT_PATH" 2>/dev/null || true)"
    issuer="${issuer#issuer=}"
    subject="${subject#subject=}"
    [ "$subject" = "CN=rcgen self signed cert" ] && [ "$issuer" = "$subject" ]
}

certificate_is_csqtt_letsencrypt() {
    local saved_ip cert_name issuer subject_alt_names
    [ -s "$CERT_PATH" ] || return 1
    [ -s "$KEY_PATH" ] || return 1
    command -v openssl >/dev/null 2>&1 || return 1
    saved_ip="$(state_value IP 2>/dev/null || true)"
    cert_name="$(state_value CERT_NAME 2>/dev/null || true)"
    is_public_ipv4 "$saved_ip" || return 1
    [ "$cert_name" = "csqtt-ip-${saved_ip//./-}" ] || return 1
    issuer="$(openssl x509 -noout -issuer -nameopt RFC2253 -in "$CERT_PATH" 2>/dev/null || true)"
    issuer="${issuer#issuer=}"
    case "$issuer" in
        *"O=Let's Encrypt"*) ;;
        *) return 1 ;;
    esac
    subject_alt_names="$(openssl x509 -noout -ext subjectAltName -in "$CERT_PATH" 2>/dev/null || true)"
    printf '%s\n' "$subject_alt_names" | grep -Fq "IP Address:${saved_ip}"
}

certificate_is_csqtt_managed() {
    certificate_is_csqtt_rcgen || certificate_is_csqtt_letsencrypt
}

needs_renewal() {
    local current_ip="$1" saved_ip
    saved_ip="$(state_value IP 2>/dev/null || true)"
    [ "$saved_ip" = "$current_ip" ] || return 0
    [ -s "$CERT_PATH" ] || return 0
    openssl x509 -noout -checkend "$RENEW_BEFORE_SECONDS" -in "$CERT_PATH" >/dev/null 2>&1 || return 0
    return 1
}

install_certificate() {
    local current_ip="$1" cert_name="$2" source_dir cert_tmp key_tmp state_tmp
    source_dir="/etc/letsencrypt/live/${cert_name}"
    [ -s "$source_dir/fullchain.pem" ] && [ -s "$source_dir/privkey.pem" ] || return 1
    cert_tmp="$(mktemp "${CONFIG_DIR}/.web_cert.XXXXXX")" || return 1
    key_tmp="$(mktemp "${CONFIG_DIR}/.web_key.XXXXXX")" || { rm -f -- "$cert_tmp"; return 1; }
    state_tmp="$(mktemp "${CONFIG_DIR}/.letsencrypt-ip.XXXXXX")" || { rm -f -- "$cert_tmp" "$key_tmp"; return 1; }
    if ! install -m 0644 "$source_dir/fullchain.pem" "$cert_tmp" || ! install -m 0600 "$source_dir/privkey.pem" "$key_tmp"; then
        rm -f -- "$cert_tmp" "$key_tmp" "$state_tmp"
        return 1
    fi
    printf 'IP=%s\nCERT_NAME=%s\n' "$current_ip" "$cert_name" > "$state_tmp"
    chmod 0600 "$state_tmp"
    mv -f -- "$cert_tmp" "$CERT_PATH"
    mv -f -- "$key_tmp" "$KEY_PATH"
    mv -f -- "$state_tmp" "$STATE_FILE"
    chmod 644 "$CERT_PATH"
    chmod 600 "$KEY_PATH" "$STATE_FILE"
}

reload_csqtt_tls() {
    if [ "$SERVICE_MANAGER" = "docker" ]; then
        docker kill --signal USR1 csqtt >/dev/null 2>&1 || return 0
    else
        systemctl kill --kill-who=main --signal USR1 csqtt >/dev/null 2>&1 || return 0
    fi
}

main() {
    local current_ip cert_name
    if [ -s "$CERT_PATH" ] && ! certificate_is_csqtt_managed; then
        log "Let’s Encrypt: обнаружен пользовательский TLS-сертификат; CSQTT не изменяет его и отключает собственное продление"
        systemctl disable --now csqtt-letsencrypt.timer >/dev/null 2>&1 || true
        return 0
    fi
    [ -x "$CERTBOT" ] || { log "Let’s Encrypt: Certbot не найден, обновление отложено"; return 0; }
    current_ip="$(public_ipv4 2>/dev/null || true)"
    [ -n "$current_ip" ] || { log "Let’s Encrypt: публичный IPv4 не определён, обновление отложено"; return 0; }
    needs_renewal "$current_ip" || return 0
    if ss -ltnH "sport = :${HTTP_PORT}" 2>/dev/null | grep -q .; then
        log "Let’s Encrypt: TCP/${HTTP_PORT} занят, обновление отложено"
        return 0
    fi
    cert_name="csqtt-ip-${current_ip//./-}"
    if ! timeout 90 "$CERTBOT" certonly --standalone --http-01-port "$HTTP_PORT" --non-interactive --agree-tos --register-unsafely-without-email --preferred-profile shortlived --ip-address "$current_ip" --cert-name "$cert_name" --force-renewal; then
        log "Let’s Encrypt: перевыпуск IP-сертификата не удался, текущий сертификат сохранён"
        return 0
    fi
    if ! install_certificate "$current_ip" "$cert_name"; then
        log "Let’s Encrypt: не удалось безопасно активировать новый сертификат"
        return 0
    fi
    reload_csqtt_tls
    log "Let’s Encrypt: IP-сертификат обновлён и TLS-конфигурация CSQTT перезагружена"
}

main "$@"
LEHELPER
    chmod 0755 "$CSQTT_LE_RENEW_HELPER"
}

install_letsencrypt_renewal_timer() {
    command -v systemctl >/dev/null 2>&1 || {
        log_warn "systemd не найден: Let’s Encrypt сертификат получен, но автоматическое продление не установлено"
        return 0
    }
    cat > "/etc/systemd/system/${CSQTT_LE_SERVICE}" << LEUNIT
[Unit]
Description=Renew CSQTT Let’s Encrypt IP certificate
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=CSQTT_DEPLOY_MODE=${DEPLOY_MODE}
ExecStart=${CSQTT_LE_RENEW_HELPER}
LEUNIT
    cat > "/etc/systemd/system/${CSQTT_LE_TIMER}" << LETIMER
[Unit]
Description=Check CSQTT Let’s Encrypt IP certificate lifetime

[Timer]
OnBootSec=10min
OnUnitInactiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
LETIMER
    systemctl daemon-reload || {
        log_warn "Не удалось обновить systemd unit для Let’s Encrypt"
        return 0
    }
    systemctl enable --now "$CSQTT_LE_TIMER" >/dev/null 2>&1 || \
        log_warn "Не удалось включить автоматическое продление Let’s Encrypt"
}

setup_letsencrypt_ip_tls() {
    local public_ip cert_name
    if web_certificate_is_user_managed; then
        rm -f -- "$CSQTT_LE_STATE_FILE"
        disable_letsencrypt_renewal_timer
        log_info "Используется заранее установленный TLS-сертификат пользователя; CSQTT сохраняет его и не заменяет Let’s Encrypt"
        return 0
    fi
    if ! ensure_letsencrypt_client; then
        return 0
    fi
    write_letsencrypt_renewal_helper
    public_ip="$(detect_public_ipv4 2>/dev/null || true)"
    if [ -z "$public_ip" ]; then
        log_warn "Публичный IPv4 не определён; WEB-панель временно останется на self-signed TLS"
        install_letsencrypt_renewal_timer
        return 0
    fi
    if letsencrypt_certificate_is_current "$public_ip"; then
        log_info "Let’s Encrypt IP-сертификат действителен; перевыпуск не требуется"
    else
        cert_name="$(letsencrypt_cert_name "$public_ip")"
        issue_letsencrypt_ip_certificate "$LE_CERTBOT_COMMAND" "$public_ip" "$cert_name" || true
    fi
    install_letsencrypt_renewal_timer
}

verify_web_panel() {
    local _ scheme code
    local probe_file="/tmp/csqtt-web-probe.$$"

    for _ in $(seq 1 24); do
        for scheme in https http; do
            code="$(curl -k -sS -o "$probe_file" -w "%{http_code}" \
                --connect-timeout 1 --max-time 2 \
                "${scheme}://127.0.0.1:${WEB_PORT}/" 2>>"$LOG_FILE" || true)"
            case "$code" in
                200|301|302|401)
                    rm -f -- "$probe_file"
                    log_info "WEB-панель ответила локальной health-проверке (${scheme}, HTTP ${code})"
                    return 0
                    ;;
            esac
        done
        sleep 0.25
    done
    rm -f -- "$probe_file"
    die "WEB-панель не ответила на локальную health-проверку порта ${WEB_PORT}"
}

ensure_docker() {
    log_step "Проверка Docker Engine..."

    if ! command -v docker >/dev/null 2>&1; then
        pkg_update
        if [ "$PKG_MGR" = "pacman" ]; then
            pkg_install docker || die "Не удалось установить Docker Engine"
        else
            pkg_install ca-certificates curl || die "Не удалось установить curl и ca-certificates для Docker"
            local installer
            installer="$(mktemp)"
            curl -fsSL https://get.docker.com -o "$installer" || die "Не удалось загрузить официальный установщик Docker"
            sh "$installer" >>"$LOG_FILE" 2>&1 || {
                rm -f "$installer"
                die "Не удалось установить Docker Engine"
            }
            rm -f "$installer"
        fi
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now docker >>"$LOG_FILE" 2>&1 || true
    elif command -v service >/dev/null 2>&1; then
        service docker start >>"$LOG_FILE" 2>&1 || true
    fi

    docker --version | tee -a "$LOG_FILE"
    docker info >>"$LOG_FILE" 2>&1 || die "Docker установлен, но демон недоступен; проверьте docker info"
    log_info "Docker Engine готов"
}

ensure_tun_device() {
    if [ -c /dev/net/tun ]; then
        chmod 666 /dev/net/tun 2>/dev/null || true
        return 0
    fi
    if command -v modprobe >/dev/null 2>&1; then
        modprobe tun >>"$LOG_FILE" 2>&1 || true
    fi
    mkdir -p /dev/net
    [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200 >>"$LOG_FILE" 2>&1 || true
    [ -c /dev/net/tun ] || die "Устройство /dev/net/tun недоступно на этом VPS"
    chmod 666 /dev/net/tun 2>/dev/null || true
}

check_kernel_compatibility() {
    [ "$(uname -s)" = "Linux" ] || die "CSQTT Server поддерживает только Linux"
    local release base major minor
    release="$(uname -r)"
    base="${release%%-*}"
    major="${base%%.*}"
    base="${base#*.}"
    minor="${base%%.*}"
    case "$major:$minor" in
        *[!0-9:]*|:*) log_warn "Не удалось разобрать версию ядра $release; решающей будет рабочая проверка TUN" ;;
        *)
            if [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -lt 5 ]; }; then
                log_warn "Ядро $release старше проверенного диапазона 5.5–7.x; установка продолжится только при успешных рабочих пробах"
            else
                log_info "Ядро Linux $release входит в поддерживаемый диапазон"
            fi
            ;;
    esac
}

load_kernel_network_modules() {
    command -v modprobe >/dev/null 2>&1 || return 0
    local module
    for module in tun nf_tables ip_tables iptable_filter iptable_nat iptable_mangle iptable_raw nf_nat nf_conntrack xt_comment xt_MASQUERADE xt_TCPMSS; do
        modprobe "$module" >>"$LOG_FILE" 2>&1 || true
    done
}

probe_tun_support() {
    ensure_tun_device
    local probe_iface="cqtprobe$(( $$ % 100000 ))"
    ip link del "$probe_iface" >>"$LOG_FILE" 2>&1 || true
    if ! ip tuntap add dev "$probe_iface" mode tun >>"$LOG_FILE" 2>&1; then
        load_kernel_network_modules
        ip link del "$probe_iface" >>"$LOG_FILE" 2>&1 || true
        if ! ip tuntap add dev "$probe_iface" mode tun >>"$LOG_FILE" 2>&1; then
            die "TUN существует, но ядро или политика VPS запрещает TUNSETIFF/CAP_NET_ADMIN"
        fi
    fi
    if ! ip link del "$probe_iface" >>"$LOG_FILE" 2>&1; then
        die "Рабочий TUN создан, но тестовый интерфейс $probe_iface не удалось удалить"
    fi
    log_info "TUN проверен реальным созданием и удалением интерфейса"
}

run_platform_preflight() {
    prog 0.35 "Совместимость ядра..."
    log_step "Проверка совместимости ядра и VPS..."
    check_kernel_compatibility
    probe_tun_support
}

write_csqtt_dockerfile() {
    local target="$1"
    cat > "$target" << 'DOCKERFILE'
# SPDX-FileCopyrightText: 2026 amurcanov
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 iptables procps && rm -rf /var/lib/apt/lists/*
COPY csqtt /usr/local/bin/csqtt
COPY network-up.sh /usr/local/lib/csqtt/network-up.sh
RUN chmod 0755 /usr/local/bin/csqtt /usr/local/lib/csqtt/network-up.sh
ENTRYPOINT ["/bin/sh", "-ec", "/usr/local/lib/csqtt/network-up.sh; exec /usr/local/bin/csqtt \"$@\"", "--"]
DOCKERFILE
}

prepare_docker_candidate() {
    local source_binary="$1" context_dir
    [ -x "$source_binary" ] || \
        die "Docker-образ нельзя собрать без установленного бинарника csqtt" "$EXIT_PREFLIGHT_FAILED"
    ensure_tun_device
    DOCKER_CONTEXT_DIR="$(mktemp -d /tmp/csqtt-docker.XXXXXX)" || \
        die "Не удалось создать Docker staging context" "$EXIT_PREFLIGHT_FAILED"
    context_dir="$DOCKER_CONTEXT_DIR"
    install -m 0755 "$source_binary" "$context_dir/csqtt" || \
        die "Не удалось подготовить Docker-бинарник" "$EXIT_PREFLIGHT_FAILED"
    write_network_helper "$context_dir/network-up.sh" || \
        die "Не удалось подготовить Docker network helper" "$EXIT_PREFLIGHT_FAILED"
    write_csqtt_dockerfile "$context_dir/Dockerfile"

    CSQTT_DOCKER_CANDIDATE_IMAGE="${CSQTT_DOCKER_IMAGE}-candidate-$$"
    docker build -t "$CSQTT_DOCKER_CANDIDATE_IMAGE" "$context_dir" >>"$LOG_FILE" 2>&1 || \
        die "Сборка Docker-образа CSQTT завершилась ошибкой" "$EXIT_PREFLIGHT_FAILED"
    probe_docker_runtime "$CSQTT_DOCKER_CANDIDATE_IMAGE"
    remove_managed_work_dir "$DOCKER_CONTEXT_DIR" || true
    DOCKER_CONTEXT_DIR=""
    log_info "Docker-образ прошёл проверку: $CSQTT_DOCKER_CANDIDATE_IMAGE"
}

setup_csqtt_docker() {
    prog 0.75 "Docker-образ..."
    [ -n "$CSQTT_DOCKER_CANDIDATE_IMAGE" ] || \
        die "Не найден проверенный Docker-кандидат" "$EXIT_PREFLIGHT_FAILED"
    docker tag "$CSQTT_DOCKER_CANDIDATE_IMAGE" "$CSQTT_DOCKER_IMAGE" || \
        die "Не удалось активировать проверенный Docker-образ"
    log_info "Проверенный Docker-образ активирован: $CSQTT_DOCKER_IMAGE"
}

probe_docker_runtime() {
    local image="${1:-$CSQTT_DOCKER_IMAGE}"
    local probe_iface="cqtd$(( $$ % 100000 ))" probe_chain="CSQTT_D$(( $$ % 1000000 ))" output
    if ! output="$(docker run --rm \
        --network host \
        --cap-drop ALL \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        --device /dev/net/tun:/dev/net/tun \
        --security-opt seccomp=unconfined \
        --env "PROBE_IFACE=$probe_iface" \
        --env "PROBE_CHAIN=$probe_chain" \
        --entrypoint /bin/sh \
        "$image" -ec '
ip tuntap add dev "$PROBE_IFACE" mode tun
ip link del "$PROBE_IFACE"
for table in filter nat mangle; do
    iptables -w 2 -t "$table" -N "$PROBE_CHAIN"
    iptables -w 2 -t "$table" -X "$PROBE_CHAIN"
done
' 2>&1)"; then
        printf '%s\n' "$output" >>"$LOG_FILE"
        die "Docker не прошёл рабочую проверку TUN или netfilter"
    fi
    printf '%s\n' "$output" >>"$LOG_FILE"
    log_info "Docker runtime проверен: TUN/netfilter"
}

start_csqtt_docker() {
    prog 0.90 "Запуск Docker..."
    ensure_tun_device
    touch /run/xtables.lock
    timeout 3 docker rm -f "$CSQTT_DOCKER_CONTAINER" >/dev/null 2>&1 || true

    docker run -d \
        --name "$CSQTT_DOCKER_CONTAINER" \
        --restart unless-stopped \
        --network host \
        --cap-drop ALL \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        --device /dev/net/tun:/dev/net/tun \
        --security-opt seccomp=unconfined \
        --stop-timeout 5 \
        --ulimit nofile=65535:65535 \
        --env-file "$CSQTT_ENV_FILE" \
        --env CSQTT_SERVICE_MANAGER=docker \
        --volume "$CSQTT_CONFIG_DIR:$CSQTT_CONFIG_DIR" \
        --volume /run/xtables.lock:/run/xtables.lock \
        "$CSQTT_DOCKER_IMAGE" \
        --listen "0.0.0.0:${PEER_PORT}" \
        --web-port "$WEB_PORT" \
        --config-dir "$CSQTT_CONFIG_DIR" >>"$LOG_FILE" 2>&1 || \
        die "Не удалось создать Docker-контейнер CSQTT"

    local state running main_pid restarts candidate_pid=0 candidate_restarts=0 found=0
    local attempts=0
    while [ "$attempts" -lt 48 ]; do
        attempts=$((attempts + 1))
        state="$(docker inspect --format '{{.State.Running}}|{{.State.Pid}}|{{.RestartCount}}' "$CSQTT_DOCKER_CONTAINER" 2>/dev/null || echo 'false|0|-1')"
        IFS='|' read -r running main_pid restarts <<< "$state"
        case "$main_pid" in ''|*[!0-9]*) main_pid=0 ;; esac
        case "$restarts" in ''|*[!0-9]*) restarts=-1 ;; esac
        if [ "$running" = "true" ] && [ "$main_pid" -gt 1 ] && ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
            candidate_pid="$main_pid"
            candidate_restarts="$restarts"
            found=1
            break
        fi
        sleep 0.25
    done

    if [ "$found" -ne 1 ]; then
        docker logs --tail 50 "$CSQTT_DOCKER_CONTAINER" 2>&1 | sed 's/^/   >> /' || true
        die "Docker CSQTT не запустился или TUN $CSQTT_IFACE не создан"
    fi

    sleep "$START_STABILITY_SECONDS"
    state="$(docker inspect --format '{{.State.Running}}|{{.State.Pid}}|{{.RestartCount}}' "$CSQTT_DOCKER_CONTAINER" 2>/dev/null || echo 'false|0|-1')"
    IFS='|' read -r running main_pid restarts <<< "$state"
    if [ "$running" != "true" ] || [ "$main_pid" != "$candidate_pid" ] || [ "$restarts" != "$candidate_restarts" ] || \
       ! ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
        docker logs --tail 50 "$CSQTT_DOCKER_CONTAINER" 2>&1 | sed 's/^/   >> /' || true
        die "Docker CSQTT вошёл в crash-loop во время стабильной проверки"
    fi

    verify_configured_network
    verify_web_panel
    finish_deployment
    prog 1.0 "Готово!"
    echo ""
    echo "✓ Деплой успешно завершён"
    echo "CSQTT_DEPLOY_OK"
    echo "   Режим:      Docker"
    echo "   Бинарник:   /usr/local/bin/csqtt"
    echo "   Конфиг:     ${CSQTT_CONFIG_DIR}"
    echo "   Контейнер:  ${CSQTT_DOCKER_CONTAINER}"
    echo "   Образ:      ${CSQTT_DOCKER_IMAGE}"
    echo "   PEER:       порт ${PEER_PORT}"
    echo "   SSH:        порт ${SSH_PORT}"
    echo "   WEB:        порт ${WEB_PORT}"
    echo "   PID:        ${candidate_pid}"
    echo "   Логи:       docker logs -f ${CSQTT_DOCKER_CONTAINER}"
    echo "   Статус:     docker ps --filter name=${CSQTT_DOCKER_CONTAINER}"
    echo ""
}

setup_csqtt_service() {
    prog 0.75 "Сервис..."
    echo "🔧 Создание systemd-сервиса CSQTT..."

    local unit_tmp
    unit_tmp="$(mktemp)"
    cat > "$unit_tmp" << CSQTTSVC
[Unit]
Description=CSQTT VPN Server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=20
StartLimitBurst=5

[Service]
Type=simple
EnvironmentFile=-${CSQTT_ENV_FILE}
Environment=CSQTT_SERVICE_MANAGER=systemd
ExecStartPre=/usr/local/lib/csqtt/network-up.sh
ExecStart=/usr/local/bin/csqtt --listen 0.0.0.0:${PEER_PORT} --web-port ${WEB_PORT} --config-dir ${CSQTT_CONFIG_DIR}
Restart=on-failure
RestartSec=1
KillMode=control-group
TimeoutStartSec=30
TimeoutStopSec=5
LimitNOFILE=65535
TasksMax=infinity

[Install]
WantedBy=multi-user.target
CSQTTSVC

    if [ ! -f /etc/systemd/system/csqtt.service ] || ! cmp -s "$unit_tmp" /etc/systemd/system/csqtt.service; then
        install -m 0644 "$unit_tmp" /etc/systemd/system/csqtt.service
        SYSTEMD_NEEDS_RELOAD=1
    fi
    rm -f "$unit_tmp"

    if [ "$SYSTEMD_NEEDS_RELOAD" -eq 1 ]; then
        systemctl daemon-reload || die "systemctl daemon-reload завершился ошибкой"
        SYSTEMD_NEEDS_RELOAD=0
    fi

    mkdir -p /etc/systemd/system/multi-user.target.wants
    ln -sfn /etc/systemd/system/csqtt.service /etc/systemd/system/multi-user.target.wants/csqtt.service
    echo "✓ Сервис csqtt.service создан и включён"
}

diagnose_systemd_failure() {
    local props result="unknown" exec_code="unknown" exec_status="unknown" restarts="unknown" active="unknown" sub="unknown" pid="0"
    props="$(systemctl show csqtt -p Result -p ExecMainCode -p ExecMainStatus -p NRestarts -p ActiveState -p SubState -p MainPID 2>/dev/null || true)"
    while IFS='=' read -r key value; do
        case "$key" in
            Result) result="$value" ;; ExecMainCode) exec_code="$value" ;; ExecMainStatus) exec_status="$value" ;;
            NRestarts) restarts="$value" ;; ActiveState) active="$value" ;; SubState) sub="$value" ;; MainPID) pid="$value" ;;
        esac
    done <<< "$props"
    log_error "systemd: active=$active/$sub result=$result code=$exec_code status=$exec_status restarts=$restarts pid=$pid"
    journalctl -u csqtt -b -n 50 --no-pager 2>/dev/null | sed 's/^/   >> /' | tee -a "$LOG_FILE" || true
}

start_csqtt() {
    if [ "$DEPLOY_MODE" = "docker" ]; then
        start_csqtt_docker
        return
    fi
    prog 0.90 "Запуск..."
    echo "🚀 Запуск CSQTT VPN Server..."

    [ -x /usr/local/bin/csqtt ] || die "Исполняемый файл /usr/local/bin/csqtt не установлен"

    # cleanup уже остановил старый runtime. Блокирующего systemctl stop здесь нет.
    if ! systemctl start csqtt; then
        # start-limit-hit после старого crash-loop: reset только по необходимости.
        systemctl reset-failed csqtt >/dev/null 2>&1 || true
        if ! systemctl start csqtt; then
            diagnose_systemd_failure
            die "systemctl start csqtt завершился ошибкой"
        fi
    fi

    local props key value active sub main_pid restarts
    local candidate_pid=0 candidate_restarts=0 attempts=0 found=0
    # Обычный успешный путь занимает несколько сотен мс; 12с — только аварийный потолок.
    while [ "$attempts" -lt 48 ]; do
        attempts=$((attempts + 1))
        active=""; sub=""; main_pid=0; restarts=0
        props="$(systemctl show csqtt -p ActiveState -p SubState -p MainPID -p NRestarts 2>/dev/null || true)"
        while IFS='=' read -r key value; do
            case "$key" in
                ActiveState) active="$value" ;; SubState) sub="$value" ;; MainPID) main_pid="$value" ;; NRestarts) restarts="$value" ;;
            esac
        done <<< "$props"
        case "$main_pid" in ''|*[!0-9]*) main_pid=0 ;; esac
        case "$restarts" in ''|*[!0-9]*) restarts=0 ;; esac

        if [ "$active" = "active" ] && [ "$sub" = "running" ] && [ "$main_pid" -gt 1 ] && \
           kill -0 "$main_pid" 2>/dev/null && ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
            candidate_pid="$main_pid"
            candidate_restarts="$restarts"
            found=1
            break
        fi
        sleep 0.25
    done

    if [ "$found" -ne 1 ]; then
        diagnose_systemd_failure
        die "CSQTT не запустился: сервис не running или TUN $CSQTT_IFACE не создан"
    fi

    # Короткое окно ловит прежний immediate signal/crash-loop без фиксированных 5 секунд.
    sleep "$START_STABILITY_SECONDS"
    active=""; sub=""; main_pid=0; restarts=0
    props="$(systemctl show csqtt -p ActiveState -p SubState -p MainPID -p NRestarts 2>/dev/null || true)"
    while IFS='=' read -r key value; do
        case "$key" in
            ActiveState) active="$value" ;; SubState) sub="$value" ;; MainPID) main_pid="$value" ;; NRestarts) restarts="$value" ;;
        esac
    done <<< "$props"
    case "$main_pid" in ''|*[!0-9]*) main_pid=0 ;; esac
    case "$restarts" in ''|*[!0-9]*) restarts=0 ;; esac

    if [ "$active" != "active" ] || [ "$sub" != "running" ] || [ "$main_pid" != "$candidate_pid" ] || \
       [ "$restarts" != "$candidate_restarts" ] || ! kill -0 "$candidate_pid" 2>/dev/null || \
       ! ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
        diagnose_systemd_failure
        die "CSQTT вошёл в crash-loop или потерял TUN во время стабильной проверки"
    fi

    verify_configured_network
    verify_web_panel
    [ "$restarts" -eq 0 ] || log_warn "Во время старта csqtt перезапустился $restarts раз(а), затем стабилизировался"
    log_info "CSQTT сервер подтверждён: PID $candidate_pid, интерфейс $CSQTT_IFACE активен"
    finish_deployment

    prog 1.0 "Готово!"
    echo ""
    echo "══════════════════════════════════════════════════════════════"
    echo "✓ Деплой успешно завершён"
    echo "CSQTT_DEPLOY_OK"
    echo "   Режим: systemd"
    echo "   Бинарник: /usr/local/bin/csqtt"
    echo "   Unit: /etc/systemd/system/csqtt.service"
    echo "   Конфиг: ${CSQTT_CONFIG_DIR}"
    echo "   NAT:  MASQUERADE (восстанавливается после reboot)"
    echo "   PEER: порт ${PEER_PORT}"
    echo "   SSH:  порт ${SSH_PORT}"
    echo "   WEB:  порт ${WEB_PORT}"
    echo "   PID:  ${candidate_pid}"
    echo "   Логи:   journalctl -u csqtt -f"
    echo "   Статус: systemctl status csqtt"
    echo "══════════════════════════════════════════════════════════════"
    echo ""
}

do_uninstall() {
    log_step "Удаление CSQTT..."

    if command -v docker >/dev/null 2>&1; then
        timeout 3 docker rm -f "$CSQTT_DOCKER_CONTAINER" >/dev/null 2>&1 || true
        timeout 5 docker image rm "$CSQTT_DOCKER_IMAGE" >/dev/null 2>&1 || true
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now "$CSQTT_LE_TIMER" >/dev/null 2>&1 || true
        systemctl stop "$CSQTT_LE_SERVICE" --no-block >/dev/null 2>&1 || true
        systemctl stop csqtt --no-block >/dev/null 2>&1 || true
        timeout 2 systemctl kill --kill-who=all --signal=SIGKILL csqtt >/dev/null 2>&1 || true
        systemctl disable csqtt >/dev/null 2>&1 || true
    fi
    pkill -9 -x csqtt >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/csqtt.service
    rm -rf /etc/systemd/system/csqtt.service.d
    rm -f /etc/systemd/system/multi-user.target.wants/csqtt.service
    rm -f "/etc/systemd/system/${CSQTT_LE_SERVICE}" "/etc/systemd/system/${CSQTT_LE_TIMER}"
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true

    if ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
        timeout 2 ip link del "$CSQTT_IFACE" 2>/dev/null || true
    fi
    cleanup_legacy_proxy_interfaces || true
    cleanup_csqtt_proxy_policy || true
    cleanup_csqtt_netfilter_rules || true

    rm -f /usr/local/bin/csqtt /usr/local/bin/csqtt-cascade
    rm -f /usr/local/bin/hev-socks5-tunnel /usr/local/bin/hev-socks5-server
    rm -rf /run/csqtt /usr/local/lib/csqtt /var/lib/csqtt /opt/csqtt-certbot
    secure_persistent_state
    # Uninstall removes runtime artifacts, not SQLite state, certificates or
    # user configuration. The server owns the transactional JSON-to-SQLite
    # migration and is the only component allowed to delete its legacy input.
    rm -f "$CSQTT_SYSCTL_FILE" "$CSQTT_UDP_SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true

    log_info "CSQTT удалён. SQLite state и конфигурация сохранены в ${CSQTT_CONFIG_DIR}"
}

do_status() {
    echo "Статус CSQTT:"
    echo ""
    if command -v docker >/dev/null 2>&1 && docker inspect "$CSQTT_DOCKER_CONTAINER" >/dev/null 2>&1; then
        if [ "$(docker inspect --format '{{.State.Running}}' "$CSQTT_DOCKER_CONTAINER" 2>/dev/null)" = "true" ]; then
            log_info "Docker-контейнер: АКТИВЕН"
        else
            log_warn "Docker-контейнер: НЕ АКТИВЕН"
        fi
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active csqtt &>/dev/null; then
        log_info "Сервис: АКТИВЕН"
    else
        log_warn "Сервис: НЕ АКТИВЕН"
    fi
    if [ -f /usr/local/bin/csqtt ]; then
        log_info "Бинарник: установлен"
    else
        log_warn "Бинарник: НЕ найден"
    fi
    if ip link show "$CSQTT_IFACE" &>/dev/null; then
        log_info "CSQTT интерфейс ($CSQTT_IFACE): активен"
    else
        log_warn "CSQTT интерфейс ($CSQTT_IFACE): не активен"
    fi
}

handle_unexpected_error() {
    local line="$1" status="$2"
    trap - ERR
    log_error "Неперехваченная ошибка deploy.sh (строка $line, exit=$status)"
    printf 'CSQTT_DEPLOY_ERROR|%s|Неперехваченная ошибка deploy.sh (строка %s, exit=%s)\n' "$DEPLOY_PHASE" "$line" "$status"
    cleanup_deploy_uploads
    case "$DEPLOY_PHASE" in
        validation) exit "$EXIT_INVALID_ARGUMENT" ;;
        preflight) exit "$EXIT_PREFLIGHT_FAILED" ;;
        *) exit "$status" ;;
    esac
}

trap 'handle_unexpected_error "$LINENO" "$?"' ERR

main() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║       CSQTT VPN Server — Installer v${SCRIPT_VERSION}                    ║"
    echo "║       PEER: ${PEER_PORT}  |  SSH: ${SSH_PORT}  | WEB: ${WEB_PORT}       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"

    local action="${1:-install}"
    check_root
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "=== CSQTT Installer v${SCRIPT_VERSION} — $(date) ===" >> "$LOG_FILE"

    case "$action" in
        status|--status|-s)       do_status ;;
        uninstall|--uninstall|-u)
            DEPLOY_PHASE="validation"
            validate_port "CSQTT_PEER_PORT" "$PEER_PORT"
            do_uninstall
            ;;
        prepare|--prepare|-p)
            DEPLOY_PHASE="validation"
            case "$DEPLOY_MODE" in
                systemd|docker) ;;
                *) die "CSQTT_DEPLOY_MODE должен быть systemd или docker" ;;
            esac
            validate_port "CSQTT_PEER_PORT" "$PEER_PORT"
            validate_port "CSQTT_SSH_PORT" "$SSH_PORT"
            validate_port "CSQTT_WEB_PORT" "$WEB_PORT"

            local total_started=$SECONDS
            detect_os
            run_timed "зависимости" install_prerequisites
            require_runtime_tools
            if [ "$DEPLOY_MODE" = "docker" ]; then
                prog 0.12 "Docker..."
                run_timed "Docker" ensure_docker
            fi
            run_timed "sysctl" setup_sysctl

            DEPLOY_PHASE="cutover"
            run_timed "переключение runtime" csqtt_cleanup
            log_info "Сервер очищен; можно загружать новый бинарник и конфигурацию"
            echo "CSQTT_DEPLOY_READY_FOR_UPLOAD"
            log_info "Общее время подготовки: $((SECONDS - total_started))с"
            ;;
        install|--install|-i|*)
            DEPLOY_PHASE="validation"
            case "$DEPLOY_MODE" in
                systemd|docker) ;;
                *) die "CSQTT_DEPLOY_MODE должен быть systemd или docker" ;;
            esac
            validate_port "CSQTT_PEER_PORT" "$PEER_PORT"
            validate_port "CSQTT_SSH_PORT" "$SSH_PORT"
            validate_port "CSQTT_WEB_PORT" "$WEB_PORT"

            local total_started=$SECONDS
            detect_os
            require_runtime_tools
            if [ "$DEPLOY_MODE" = "docker" ]; then
                prog 0.12 "Docker..."
                run_timed "Docker" ensure_docker
            fi

            run_timed "проверка upload" prepare_uploaded_release
            DEPLOY_PHASE="cutover"
            run_timed "бинарник" setup_csqtt_binary
            run_timed "preflight" run_platform_preflight
            if [ "$DEPLOY_MODE" = "docker" ]; then
                run_timed "Docker preflight" prepare_docker_candidate /usr/local/bin/csqtt
            fi
            detect_firewall
            run_timed "NAT/firewall" setup_nat_and_firewall
            install_network_helper
            setup_csqtt_environment
            run_timed "Let’s Encrypt" setup_letsencrypt_ip_tls
            DEPLOY_PHASE="activation"
            if [ "$DEPLOY_MODE" = "docker" ]; then
                run_timed "Docker activation" setup_csqtt_docker
            else
                run_timed "systemd unit" setup_csqtt_service
            fi
            run_timed "запуск" start_csqtt
            log_info "Общее время deploy.sh: $((SECONDS - total_started))с"
            ;;
    esac
}

main "$@"
