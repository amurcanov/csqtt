#!/bin/bash
# SPDX-FileCopyrightText: 2026 amurcanov
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export TERM="${TERM:-xterm}"

readonly SCRIPT_VERSION="2.1.9"
readonly CSQTT_WIRE_PROTOCOL_REVISION="CSQTT-WIRE-3"
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
readonly CSQTT_RUNTIME_ARCHIVE_DIR="${CSQTT_CONFIG_DIR}/runtime-archive"
readonly UPLOAD_BINARY="/tmp/.csqtt-upload-server"
readonly UPLOAD_ENV_FILE="/tmp/.csqtt-upload-web.env"
readonly UPLOAD_OVERRIDES_FILE="/tmp/.csqtt-upload-overrides.json"
readonly CSQTT_SYSCTL_FILE="/etc/sysctl.d/99-csqtt.conf"
readonly CSQTT_UDP_SYSCTL_FILE="/etc/sysctl.d/99-csqtt-udp-buffers.conf"
readonly IPT_COMMENT="CSQTT_MANAGED"
readonly CSQTT_DOCKER_IMAGE="csqtt:2.1.9"
readonly CSQTT_DOCKER_CONTAINER="csqtt"
readonly CSQTT_DOCKER_PREREQ_SERVICE="csqtt-docker-prereq.service"
readonly CSQTT_DOCKER_PREREQ_HELPER="/usr/local/lib/csqtt/docker-prereq.sh"
readonly CSQTT_RUNTIME_DIR="/run/csqtt"
readonly CSQTT_DOCKER_NETWORK_READY="${CSQTT_RUNTIME_DIR}/docker-network.ready"
readonly XT_WAIT="${CSQTT_XT_WAIT:-2}"
readonly START_STABILITY_SECONDS="${CSQTT_START_STABILITY_SECONDS:-4}"
readonly DOCKER_BUILD_TIMEOUT_SECONDS="${CSQTT_DOCKER_BUILD_TIMEOUT_SECONDS:-180}"
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

validate_positive_seconds() {
    local name="$1" value="$2"
    case "$value" in
        ''|*[!0-9]*) die "$name должен быть положительным числом секунд, получено: $value" ;;
    esac
    if [ "$value" -lt 1 ] || [ "$value" -gt 900 ]; then
        die "$name должен быть в диапазоне 1..900, получено: $value"
    fi
}

validate_distinct_network_ports() {
    [ "$PEER_PORT" != "$SSH_PORT" ] || die "CSQTT_PEER_PORT не может совпадать с SSH-портом"
    [ "$PEER_PORT" != "$WEB_PORT" ] || die "CSQTT_PEER_PORT не может совпадать с WEB-портом"
    [ "$PEER_PORT" != "$LE_HTTP_PORT" ] || die "CSQTT_PEER_PORT не может совпадать с HTTP-портом"
    [ "$WEB_PORT" != "$SSH_PORT" ] || die "CSQTT_WEB_PORT не может совпадать с SSH-портом"
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

csqtt_systemd_unit_exists() {
    command -v systemctl >/dev/null 2>&1 || return 1
    local state
    state="$(systemctl show --value -p LoadState csqtt 2>/dev/null || true)"
    [ -n "$state" ] && [ "$state" != "not-found" ]
}

csqtt_systemd_unit_is_managed() {
    csqtt_systemd_unit_exists || return 1
    local unit
    unit="$(systemctl cat csqtt 2>/dev/null || true)"
    printf '%s\n' "$unit" | grep -Eq '(/usr/local/bin/csqtt|/usr/local/lib/csqtt/)'
}

csqtt_docker_container_exists() {
    command -v docker >/dev/null 2>&1 && docker inspect "$CSQTT_DOCKER_CONTAINER" >/dev/null 2>&1
}

docker_container_runs_csqtt() {
    local container="$1" container_id proc pid cgroup executable command_line details
    docker inspect "$container" >/dev/null 2>&1 || return 1
    details="$(docker inspect --format '{{.Name}}|{{.Config.Image}}|{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{range .Mounts}}{{.Source}}:{{.Destination}}|{{end}}' "$container" 2>/dev/null || true)"
    case "$details" in
        *'|csqtt|'*|*'|csqtt:'*|*'|csqtt-docker-'*|*'/usr/local/bin/csqtt'*|*":${CSQTT_CONFIG_DIR}"*) return 0 ;;
    esac
    if docker top "$container" -eo pid,args 2>/dev/null | awk '
NR > 1 && $0 ~ /(^|[[:space:]])\/usr\/local\/bin\/csqtt([[:space:]]|$)/ { found = 1 }
END { exit !found }
'; then
        return 0
    fi
    container_id="$(docker inspect --format '{{.Id}}' "$container" 2>/dev/null || true)"
    [ -n "$container_id" ] || return 1
    for proc in /proc/[0-9]*; do
        pid="${proc##*/}"
        cgroup="$(cat "$proc/cgroup" 2>/dev/null || true)"
        case "$cgroup" in
            *"docker-${container_id}.scope"*|*"/docker/${container_id}"*) ;;
            *) continue ;;
        esac
        executable="$(readlink "$proc/exe" 2>/dev/null || true)"
        case "$executable" in
            /usr/local/bin/csqtt|'/usr/local/bin/csqtt (deleted)') return 0 ;;
        esac
        command_line="$({ tr '\0' ' ' < "$proc/cmdline"; } 2>/dev/null || true)"
        case " $command_line " in
            *" /usr/local/bin/csqtt "*|*" --config-dir ${CSQTT_CONFIG_DIR} "*) return 0 ;;
        esac
    done
    return 1
}

csqtt_persistent_state_exists() {
    [ -f "$CSQTT_ENV_FILE" ] || [ -f "${CSQTT_CONFIG_DIR}/${CSQTT_DATABASE_FILE}" ] || \
        [ -f "${CSQTT_CONFIG_DIR}/${CSQTT_LEGACY_MIGRATION_JSON}" ] || \
        [ -f "${CSQTT_CONFIG_DIR}/${CSQTT_LEGACY_MIGRATION_IMPORTED_JSON}" ] || \
        [ -f "${CSQTT_CONFIG_DIR}/web_cert.pem" ] || [ -f "${CSQTT_CONFIG_DIR}/web_key.pem" ]
}

peer_port_listeners() {
    ss -H -lunp "sport = :${PEER_PORT}" 2>/dev/null || true
}

peer_port_listener_pids() {
    peer_port_listeners | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -un || true
}

docker_container_for_pid() {
    local pid="$1" cgroup container_id
    command -v docker >/dev/null 2>&1 || return 1
    cgroup="$(cat "/proc/$pid/cgroup" 2>/dev/null || true)"
    container_id="$(printf '%s\n' "$cgroup" | sed -nE 's#.*docker-([0-9a-f]{12,64})\.scope.*#\1#p; s#.*/docker/([0-9a-f]{12,64}).*#\1#p' | head -n 1)"
    [ -n "$container_id" ] || return 1
    docker inspect "$container_id" >/dev/null 2>&1 || return 1
    printf '%s\n' "$container_id"
}

csqtt_process_is_owned() {
    local pid="$1" executable command_line
    case "$pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ -r "/proc/$pid/cmdline" ] || return 1
    executable="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    case "$executable" in
        /usr/local/bin/csqtt|'/usr/local/bin/csqtt (deleted)'|/usr/local/lib/csqtt/*|'/usr/local/lib/csqtt/'*' (deleted)') return 0 ;;
    esac
    command_line="$({ tr '\0' ' ' < "/proc/$pid/cmdline"; } 2>/dev/null || true)"
    case " $command_line " in
        *" --config-dir ${CSQTT_CONFIG_DIR} "*|*" /usr/local/bin/csqtt "*|*" /usr/local/lib/csqtt/"*) ;;
        *) return 1 ;;
    esac
    return 0
}

csqtt_process_owns_peer_port() { csqtt_process_is_owned "$1"; }

all_csqtt_process_pids() {
    local proc pid
    for proc in /proc/[0-9]*; do
        pid="${proc##*/}"
        csqtt_process_is_owned "$pid" && printf '%s\n' "$pid"
    done
    return 0
}

csqtt_peer_port_is_owned() {
    local pid
    while IFS= read -r pid; do
        csqtt_process_owns_peer_port "$pid" && return 0
    done < <(peer_port_listener_pids)
    return 1
}

force_stop_csqtt_processes() {
    local pid attempt found
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
        found=0
        while IFS= read -r pid; do
            found=1
            log_warn "Принудительное завершение CSQTT: PID $pid"
            if [ "$attempt" -le 2 ]; then
                kill -TERM "$pid" 2>/dev/null || true
            else
                kill -KILL "$pid" 2>/dev/null || true
            fi
        done < <(all_csqtt_process_pids)
        if [ "$found" -eq 0 ]; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

force_release_peer_port() {
    local attempt pid container found
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        [ -z "$(peer_port_listeners)" ] && return 0
        found=0
        while IFS= read -r pid; do
            [ -n "$pid" ] || continue
            found=1
            container="$(docker_container_for_pid "$pid" 2>/dev/null || true)"
            if [ -n "$container" ]; then
                log_warn "Принудительное удаление Docker runtime на UDP/${PEER_PORT}: ${container:0:12}"
                docker update --restart=no "$container" >/dev/null 2>&1 || true
                docker rm -f "$container" >/dev/null 2>&1 || true
            elif [ "$attempt" -le 2 ]; then
                log_warn "Принудительное завершение runtime на UDP/${PEER_PORT}: PID $pid"
                kill -TERM "$pid" 2>/dev/null || true
            else
                log_warn "Принудительное завершение runtime на UDP/${PEER_PORT}: PID $pid"
                kill -KILL "$pid" 2>/dev/null || true
            fi
        done < <(peer_port_listener_pids)
        if [ "$found" -eq 0 ]; then
            log_error "UDP/${PEER_PORT} занят runtime без доступного PID"
            peer_port_listeners | tee -a "$LOG_FILE" >&2
            return 1
        fi
        sleep 0.2
    done
    peer_port_listeners | tee -a "$LOG_FILE" >&2
    return 1
}

assert_peer_port_is_available() {
    local listeners
    listeners="$(peer_port_listeners)"
    [ -z "$listeners" ] && return 0
    log_warn "UDP/${PEER_PORT} занят; выполняется принудительное освобождение"
    force_release_peer_port || die "Не удалось принудительно освободить UDP/${PEER_PORT}"
    [ -z "$(peer_port_listeners)" ] || die "UDP/${PEER_PORT} остался занят после принудительной очистки"
}

archive_csqtt_docker_state() {
    local container="$1" container_id archive_dir source base copied=0
    container_id="$(docker inspect --format '{{.Id}}' "$container" 2>/dev/null || true)"
    [ -n "$container_id" ] || return 0
    archive_dir="${CSQTT_RUNTIME_ARCHIVE_DIR}/docker-${container_id:0:12}-$(date +%s)"
    umask 077
    mkdir -p "$archive_dir" || die "Не удалось подготовить архив состояния Docker CSQTT"
    for source in /etc/csqtt/csqtt.db /etc/csqtt/csqtt.db-wal /etc/csqtt/csqtt.db-shm /etc/csqtt/passwords.json /etc/csqtt/passwords.json.imported; do
        base="${source##*/}"
        if docker cp "${container}:${source}" "${archive_dir}/${base}" >/dev/null 2>&1; then
            chmod 600 "${archive_dir}/${base}" 2>/dev/null || true
            copied=1
        fi
    done
    if [ "$copied" -eq 1 ]; then
        log_info "Состояние Docker CSQTT сохранено: $archive_dir"
    else
        rmdir "$archive_dir" >/dev/null 2>&1 || true
    fi
}

stop_and_archive_csqtt_docker_container() {
    local container="$1" name running
    docker inspect "$container" >/dev/null 2>&1 || return 0
    name="$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null || printf '%s' "$container")"
    name="${name#/}"
    docker update --restart=no "$container" >/dev/null 2>&1 || true
    running="$(docker inspect --format '{{.State.Running}}' "$container" 2>/dev/null || printf false)"
    if [ "$running" = "true" ]; then
        timeout 10 docker stop --time 5 "$container" >/dev/null 2>&1 || true
        if [ "$(docker inspect --format '{{.State.Running}}' "$container" 2>/dev/null || printf false)" = "true" ]; then
            docker kill "$container" >/dev/null 2>&1 || true
        fi
    fi
    archive_csqtt_docker_state "$container"
    timeout 10 docker rm -f "$container" >/dev/null 2>&1 || \
        die "Не удалось остановить старый Docker-контейнер CSQTT"
}

remove_all_csqtt_docker_containers() {
    command -v docker >/dev/null 2>&1 || return 0
    local container name
    while IFS= read -r container; do
        [ -n "$container" ] || continue
        docker_container_runs_csqtt "$container" || continue
        name="$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null || printf '%s' "$container")"
        name="${name#/}"
        log_info "Остановка Docker runtime CSQTT: $name"
        stop_and_archive_csqtt_docker_container "$container"
    done < <(docker ps -aq --no-trunc 2>/dev/null || true)
}

systemd_unit_runs_csqtt() {
    local unit="$1" content
    content="$(systemctl cat "$unit" 2>/dev/null || true)"
    if printf '%s\n' "$content" | grep -Eq '(/usr/local/bin/csqtt|/usr/local/lib/csqtt/)'; then
        return 0
    fi
    return 1
}

list_csqtt_systemd_units() {
    command -v systemctl >/dev/null 2>&1 || return 0
    local unit
    while IFS= read -r unit; do
        case "$unit" in
            *.service) ;;
            *) continue ;;
        esac
        if systemd_unit_runs_csqtt "$unit"; then
            printf '%s\n' "$unit"
        fi
    done < <({
        systemctl list-units --type=service --all --no-legend --plain 2>/dev/null || true
        systemctl list-unit-files --type=service --no-legend --plain 2>/dev/null || true
    } | awk '{print $1}' | sort -u)
    return 0
}

stop_all_running_csqtt_systemd_units() {
    command -v systemctl >/dev/null 2>&1 || return 0
    local unit
    while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        log_info "Остановка systemd runtime CSQTT: $unit"
        if ! timeout 10 systemctl stop "$unit" >/dev/null 2>&1; then
            log_warn "systemctl stop завершился с ошибкой для $unit; проверяется фактическое состояние"
        fi
        if systemctl is-active --quiet "$unit"; then
            timeout 2 systemctl kill --kill-who=all --signal=SIGKILL "$unit" >/dev/null 2>&1 || true
        fi
        if systemctl is-active --quiet "$unit"; then
            die "Не удалось остановить systemd runtime CSQTT: $unit"
        fi
        systemctl disable "$unit" >/dev/null 2>&1 || true
    done < <(list_csqtt_systemd_units)
    return 0
}

remove_all_csqtt_systemd_units() {
    command -v systemctl >/dev/null 2>&1 || return 0
    local unit fragment
    while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        fragment="$(systemctl show --value -p FragmentPath "$unit" 2>/dev/null || true)"
        case "$fragment" in
            /etc/systemd/system/*)
                rm -f -- "$fragment"
                rm -rf -- "${fragment}.d"
                rm -f -- "/etc/systemd/system/multi-user.target.wants/${unit}"
                SYSTEMD_NEEDS_RELOAD=1
                ;;
        esac
    done < <(list_csqtt_systemd_units)
    return 0
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
        die "Скрипт должен быть запущен от root. Если sudo отсутствует, зайдите под root и запустите: bash $0 $*"
    fi
}

OS_ID="" ; PKG_MGR=""

detect_os() {
    log_step "Определение операционной системы..."
    if [ ! -f /etc/os-release ]; then
        die "Файл /etc/os-release не найден."
    fi
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
    if ! command -v sysctl >/dev/null 2>&1; then
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
    if [ "$DEPLOY_MODE" = "systemd" ]; then
        command -v systemctl >/dev/null 2>&1 || die "systemctl не найден. Для native-установки нужен VPS с systemd."
    fi
    case "$(uname -m)" in
        x86_64|amd64) log_info "Архитектура VPS: amd64" ;;
        aarch64|arm64) log_info "Архитектура VPS: ARM64" ;;
        armv7l|armv7|armhf) log_info "Архитектура VPS: ARM32" ;;
        *) die "Архитектура VPS $(uname -m) не поддерживается. Поддерживаются: x86_64, aarch64, armv7l." ;;
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
    local table="$1" chain="$2" marker="$3" i numbers number
    local -a targs=()
    [ "$table" = "filter" ] || targs=(-t "$table")
    for i in 1 2 3 4 5 6 7 8; do
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

cleanup_csqtt_netfilter_rules() {
    local table chain marker
    for marker in "$IPT_COMMENT" CSQTT_MIRRORED CSQTT_TPROXY CSQTT_LOCAL_SOCKS CSQTT_LOCAL_SOCKS_MARK CSQTT_SOCKS CSQTT_CASCADE_NO_QUIC; do
        for table in filter nat mangle raw; do
            for chain in INPUT FORWARD PREROUTING POSTROUTING OUTPUT; do
                delete_marked_rules "$table" "$chain" "$marker"
            done
        done
    done
}

secure_persistent_state() {
    [ -d "$CSQTT_CONFIG_DIR" ] || return 0
    chmod 700 "$CSQTT_CONFIG_DIR" 2>/dev/null || true
    [ -d "$CSQTT_RUNTIME_ARCHIVE_DIR" ] && chmod 700 "$CSQTT_RUNTIME_ARCHIVE_DIR" 2>/dev/null || true

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

ensure_csqtt_directory() {
    local path="$1" mode="$2"
    if [ -L "$path" ] || [ ! -d "$path" ]; then
        rm -rf -- "$path" || die "Не удалось очистить путь CSQTT: $path"
    fi
    mkdir -p -- "$path" || die "Не удалось подготовить каталог CSQTT: $path"
    chmod "$mode" "$path" || die "Не удалось установить права на каталог CSQTT: $path"
}

clear_runtime_config_preserving_database() {
    local entry base
    ensure_csqtt_directory "$CSQTT_CONFIG_DIR" 700
    shopt -s nullglob dotglob
    for entry in "$CSQTT_CONFIG_DIR"/*; do
        base="${entry##*/}"
        case "$base" in
            "$CSQTT_DATABASE_FILE"|"$CSQTT_DATABASE_WAL_FILE"|"$CSQTT_DATABASE_SHM_FILE"|"$CSQTT_LEGACY_MIGRATION_JSON"|"$CSQTT_LEGACY_MIGRATION_IMPORTED_JSON"|web_cert.pem|web_key.pem|letsencrypt-ip.env|runtime-archive) continue ;;
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
    if command -v docker >/dev/null 2>&1 && [ -n "$CSQTT_DOCKER_CANDIDATE_IMAGE" ]; then
        docker image rm "$CSQTT_DOCKER_CANDIDATE_IMAGE" >/dev/null 2>&1 || true
        CSQTT_DOCKER_CANDIDATE_IMAGE=""
    fi
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
    local uploaded_wire_protocol
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
    uploaded_wire_protocol="$(timeout 5 "$UPLOAD_BINARY" --protocol-revision 2>/dev/null || true)"
    [ "$uploaded_wire_protocol" = "$CSQTT_WIRE_PROTOCOL_REVISION" ] || \
        die "Загруженный бинарник CSQTT несовместим с этой версией деплоя" "$EXIT_PREFLIGHT_FAILED"
    log_info "Загруженный бинарник соответствует ревизии протокола $CSQTT_WIRE_PROTOCOL_REVISION"
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

remove_csqtt_tun_interface() {
    local attempt waited=0
    if ! ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
        return 0
    fi

    log_warn "Обнаружен остаточный TUN-интерфейс $CSQTT_IFACE; выполняется восстановление runtime"
    for attempt in 1 2 3 4; do
        if timeout 2 ip link del "$CSQTT_IFACE" >>"$LOG_FILE" 2>&1; then
            waited=0
            while [ "$waited" -lt 20 ]; do
                if ! ip link show "$CSQTT_IFACE" >/dev/null 2>&1; then
                    log_info "Остаточный TUN-интерфейс $CSQTT_IFACE удалён"
                    return 0
                fi
                sleep 0.1
                waited=$((waited + 1))
            done
        fi
        sleep 0.2
    done

    ip -d link show "$CSQTT_IFACE" 2>&1 | tee -a "$LOG_FILE" >&2 || true
    return 1
}

csqtt_cleanup() {
    prog 0.15 "Очистка..."
    echo "🧹 Переключение со старой установки CSQTT..."

    local had_old_install=0 managed_systemd_unit=0
    if csqtt_systemd_unit_is_managed; then
        managed_systemd_unit=1
    fi
    if [ -e /usr/local/bin/csqtt ] || [ -d /usr/local/lib/csqtt ] || \
       [ "$managed_systemd_unit" -eq 1 ] || csqtt_docker_container_exists || \
       csqtt_persistent_state_exists || ip link show "$CSQTT_IFACE" >/dev/null 2>&1 || \
       csqtt_peer_port_is_owned; then
        had_old_install=1
    fi

    remove_all_csqtt_docker_containers

    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$CSQTT_LE_TIMER" --no-block >/dev/null 2>&1 || true
        timeout 10 systemctl stop "$CSQTT_LE_SERVICE" >/dev/null 2>&1 || true
        stop_all_running_csqtt_systemd_units
        systemctl disable "$CSQTT_DOCKER_PREREQ_SERVICE" >/dev/null 2>&1 || true
    fi

    force_stop_csqtt_processes || die "Не удалось завершить процессы CSQTT"
    remove_all_csqtt_systemd_units
    [ -e "/etc/systemd/system/${CSQTT_DOCKER_PREREQ_SERVICE}" ] && SYSTEMD_NEEDS_RELOAD=1
    rm -f "/etc/systemd/system/${CSQTT_DOCKER_PREREQ_SERVICE}"
    rm -f "/etc/systemd/system/docker.service.requires/${CSQTT_DOCKER_PREREQ_SERVICE}"
    rm -f "/etc/systemd/system/docker.service.wants/${CSQTT_DOCKER_PREREQ_SERVICE}"
    if [ "$SYSTEMD_NEEDS_RELOAD" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || die "systemctl daemon-reload завершился ошибкой после удаления старого runtime"
        SYSTEMD_NEEDS_RELOAD=0
    fi
    rm -f /usr/local/bin/csqtt
    rm -rf /usr/local/lib/csqtt
    clear_runtime_config_preserving_database

    assert_peer_port_is_available

    cleanup_legacy_proxy_interfaces
    remove_csqtt_tun_interface || die "Не удалось освободить TUN-интерфейс $CSQTT_IFACE; переключение отменено"
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
SYSEOF

    cat > "$CSQTT_UDP_SYSCTL_FILE" << 'SYSEOF'
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
SYSEOF

    sysctl -p "$CSQTT_SYSCTL_FILE" >>"$LOG_FILE" 2>&1 || log_warn "Не удалось применить обязательные параметры маршрутизации"
    sysctl -p "$CSQTT_UDP_SYSCTL_FILE" >>"$LOG_FILE" 2>&1 || log_warn "Ядро ограничило лимиты UDP-буферов; сервер продолжит работу с доступными значениями"

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
    fw_add_input_tcp "$WEB_PORT"
    fw_add_input_tcp "$LE_HTTP_PORT"

    fw_add_forward

    fw_add_masquerade "$iface" "10.66.67.0/24"
    
    fw_add_mss_clamping "10.66.67.0/24"

    echo "✓ NAT: MASQUERADE на $iface для 10.66.67.0/24"
    echo "✓ Порты CSQTT: ${PEER_PORT}/udp(PEER), ${WEB_PORT}/tcp(WEB), ${LE_HTTP_PORT}/tcp(LE)"
    echo "✓ TCP MSS Clamping включен"
}

write_network_helper() {
    local target="$1"
    cat > "$target" << NETEOF
#!/bin/sh
set -eu
    PEER_PORT="$PEER_PORT"
WEB_PORT="$WEB_PORT"
LE_HTTP_PORT="$LE_HTTP_PORT"
CSQTT_IFACE="$CSQTT_IFACE"
IPT_COMMENT="$IPT_COMMENT"
SUBNET="10.66.67.0/24"
XT_WAIT="$XT_WAIT"
CSQTT_RUNTIME_DIR="$CSQTT_RUNTIME_DIR"
NETWORK_READY_FILE="$CSQTT_DOCKER_NETWORK_READY"

command -v ip >/dev/null 2>&1 || exit 20
command -v iptables >/dev/null 2>&1 || exit 21
[ -w /proc/sys/net/ipv4/ip_forward ] && echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
[ -f "\$NETWORK_READY_FILE" ] && exit 0

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

WAN_IFACE=""
network_waited=0
while [ "\$network_waited" -lt 90 ]; do
    candidate_iface=\$(detect_wan_interface || true)
    if [ -n "\$candidate_iface" ] && ip link show "\$candidate_iface" >/dev/null 2>&1 && \
       ip -o -4 route show default 2>/dev/null | grep -q .; then
        WAN_IFACE="\$candidate_iface"
        break
    fi
    network_waited=\$((network_waited + 1))
    sleep 1
done
[ -n "\$WAN_IFACE" ] || exit 22

ipt() { iptables -w "\$XT_WAIT" "\$@"; }
ipt -C INPUT -p udp --dport "\$PEER_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I INPUT -p udp --dport "\$PEER_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C INPUT -p tcp --dport "\$WEB_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I INPUT -p tcp --dport "\$WEB_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C INPUT -p tcp --dport "\$LE_HTTP_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I INPUT -p tcp --dport "\$LE_HTTP_PORT" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C INPUT -i "\$CSQTT_IFACE" -s "\$SUBNET" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I INPUT -i "\$CSQTT_IFACE" -s "\$SUBNET" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C FORWARD -i "\$CSQTT_IFACE" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I FORWARD -i "\$CSQTT_IFACE" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -C FORWARD -o "\$CSQTT_IFACE" -m comment --comment "\$IPT_COMMENT" -j ACCEPT 2>/dev/null || ipt -I FORWARD -o "\$CSQTT_IFACE" -m comment --comment "\$IPT_COMMENT" -j ACCEPT
ipt -t nat -C POSTROUTING -s "\$SUBNET" -o "\$WAN_IFACE" -m comment --comment "\$IPT_COMMENT" -j MASQUERADE 2>/dev/null || ipt -t nat -A POSTROUTING -s "\$SUBNET" -o "\$WAN_IFACE" -m comment --comment "\$IPT_COMMENT" -j MASQUERADE
ipt -t mangle -C FORWARD -s "\$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "\$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ipt -t mangle -I FORWARD -s "\$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "\$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu
ipt -t mangle -C FORWARD -d "\$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "\$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ipt -t mangle -I FORWARD -d "\$SUBNET" -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "\$IPT_COMMENT" -j TCPMSS --clamp-mss-to-pmtu
umask 077
mkdir -p "\$CSQTT_RUNTIME_DIR"
: > "\$NETWORK_READY_FILE"
NETEOF
    chmod 0755 "$target"
}

write_tun_recovery_helper() {
    local target="$1"
    cat > "$target" << RECOVEREOF
#!/bin/sh
set -eu
CSQTT_IFACE="$CSQTT_IFACE"
PEER_PORT="$PEER_PORT"
CSQTT_CONFIG_DIR="$CSQTT_CONFIG_DIR"

peer_port_is_busy() {
    ss -H -lun "sport = :\$PEER_PORT" 2>/dev/null | grep -q .
}

peer_port_pids() {
    ss -H -lunp "sport = :\$PEER_PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -un || true
}

csqtt_process_is_owned() {
    pid="\$1"
    [ -r "/proc/\$pid/cmdline" ] || return 1
    executable="\$(readlink "/proc/\$pid/exe" 2>/dev/null || true)"
    case "\$executable" in
        /usr/local/bin/csqtt|'/usr/local/bin/csqtt (deleted)'|/usr/local/lib/csqtt/*|'/usr/local/lib/csqtt/'*' (deleted)') return 0 ;;
    esac
    command_line="\$({ tr '\\0' ' ' < "/proc/\$pid/cmdline"; } 2>/dev/null || true)"
    case " \$command_line " in
        *" --config-dir \$CSQTT_CONFIG_DIR "*|*" /usr/local/bin/csqtt "*|*" /usr/local/lib/csqtt/"*) return 0 ;;
        *) return 1 ;;
    esac
}

release_owned_peer_port() {
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        peer_port_is_busy || return 0
        pids="\$(peer_port_pids)"
        if [ -z "\$pids" ]; then
            echo "[CSQTT] UDP/\$PEER_PORT is occupied by a runtime without visible PID" >&2
            ss -H -lunp "sport = :\$PEER_PORT" >&2 || true
            return 24
        fi
        for pid in \$pids; do
            if [ "\$attempt" -le 2 ]; then
                echo "[CSQTT] UDP/\$PEER_PORT runtime PID \$pid; terminating" >&2
                kill -TERM "\$pid" 2>/dev/null || true
            else
                echo "[CSQTT] UDP/\$PEER_PORT runtime PID \$pid; killing" >&2
                kill -KILL "\$pid" 2>/dev/null || true
            fi
        done
        sleep 0.2
    done
    echo "[CSQTT] UDP/\$PEER_PORT did not release" >&2
    ss -H -lunp "sport = :\$PEER_PORT" >&2 || true
    return 24
}

release_owned_peer_port || exit \$?

if ! ip link show "\$CSQTT_IFACE" >/dev/null 2>&1; then
    exit 0
fi

echo "[CSQTT] stale TUN interface \$CSQTT_IFACE detected; recovering runtime" >&2
for attempt in 1 2 3 4; do
    timeout 2 ip link del "\$CSQTT_IFACE" >/dev/null 2>&1 || true
    if ! ip link show "\$CSQTT_IFACE" >/dev/null 2>&1; then
        echo "[CSQTT] stale TUN interface \$CSQTT_IFACE removed" >&2
        exit 0
    fi
    sleep 0.2
done

ip -d link show "\$CSQTT_IFACE" >&2 || true
echo "[CSQTT] unable to release TUN interface \$CSQTT_IFACE" >&2
exit 23
RECOVEREOF
    chmod 0755 "$target"
}

install_network_helper() {
    ensure_csqtt_directory /usr/local/lib/csqtt 755
    write_network_helper /usr/local/lib/csqtt/network-up.sh
    write_tun_recovery_helper /usr/local/lib/csqtt/tun-recover.sh
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
    ensure_csqtt_directory "$CSQTT_CONFIG_DIR" 700
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
    ensure_csqtt_directory /usr/local/lib/csqtt 755
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
    local attempt scheme code
    local probe_file="/tmp/csqtt-web-probe.$$"

    for attempt in $(seq 1 24); do
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

install_docker_boot_prerequisite() {
    command -v systemctl >/dev/null 2>&1 || \
        die "Docker-режим требует systemd для подготовки TUN до автозапуска контейнера"

    ensure_csqtt_directory /usr/local/lib/csqtt 755
    cat > "$CSQTT_DOCKER_PREREQ_HELPER" << 'PREREQ'
#!/bin/sh
set -eu

if [ ! -c /dev/net/tun ]; then
    command -v modprobe >/dev/null 2>&1 && modprobe tun || true
    mkdir -p /dev/net
    [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
fi

[ -c /dev/net/tun ] || exit 20
chmod 666 /dev/net/tun 2>/dev/null || true
mkdir -p /run/csqtt
chmod 0755 /run/csqtt 2>/dev/null || true
rm -f /run/csqtt/docker-network.ready
touch /run/xtables.lock
chmod 600 /run/xtables.lock 2>/dev/null || true
PREREQ
    chmod 0755 "$CSQTT_DOCKER_PREREQ_HELPER"

    local unit_tmp
    unit_tmp="$(mktemp)"
    cat > "$unit_tmp" << PREREQUNIT
[Unit]
Description=Prepare CSQTT Docker TUN and xtables lock
After=local-fs.target
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${CSQTT_DOCKER_PREREQ_HELPER}

[Install]
RequiredBy=docker.service
PREREQUNIT
    install -m 0644 "$unit_tmp" "/etc/systemd/system/${CSQTT_DOCKER_PREREQ_SERVICE}"
    rm -f "$unit_tmp"
    systemctl daemon-reload || die "Не удалось обновить systemd для Docker prerequisites"
    systemctl enable "$CSQTT_DOCKER_PREREQ_SERVICE" >/dev/null 2>&1 || \
        die "Не удалось включить Docker prerequisites"
    "$CSQTT_DOCKER_PREREQ_HELPER" || \
        die "Не удалось обновить Docker runtime prerequisites"
    systemctl start "$CSQTT_DOCKER_PREREQ_SERVICE" || \
        die "Не удалось подготовить TUN/xtables lock для Docker"
}

write_csqtt_dockerfile() {
    local target="$1"
    cat > "$target" << 'DOCKERFILE'
# SPDX-FileCopyrightText: 2026 amurcanov
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
FROM alpine:3.21
ARG CSQTT_BUILD_DNS_PRIMARY
ARG CSQTT_BUILD_DNS_SECONDARY
RUN set -eu; if [ -n "${CSQTT_BUILD_DNS_PRIMARY:-}" ]; then printf 'nameserver %s\n' "$CSQTT_BUILD_DNS_PRIMARY" > /etc/resolv.conf; fi; if [ -n "${CSQTT_BUILD_DNS_SECONDARY:-}" ]; then printf 'nameserver %s\n' "$CSQTT_BUILD_DNS_SECONDARY" >> /etc/resolv.conf; fi; timeout -k 5s 120s apk add --no-cache --no-progress ca-certificates iproute2 iptables; rm -rf /var/cache/apk/*
COPY csqtt /usr/local/bin/csqtt
COPY network-up.sh /usr/local/lib/csqtt/network-up.sh
COPY tun-recover.sh /usr/local/lib/csqtt/tun-recover.sh
RUN chmod 0755 /usr/local/bin/csqtt /usr/local/lib/csqtt/network-up.sh /usr/local/lib/csqtt/tun-recover.sh
ENTRYPOINT ["/bin/sh", "-ec", "/usr/local/lib/csqtt/network-up.sh; /usr/local/lib/csqtt/tun-recover.sh; exec /usr/local/bin/csqtt \"$@\"", "--"]
DOCKERFILE
}

docker_build_candidate_image() {
    local image="$1" context_dir="$2" primary_log fallback_log
    primary_log="$(mktemp)" || return 1
    if timeout -k 15s "${DOCKER_BUILD_TIMEOUT_SECONDS}s" docker build --network host -t "$image" "$context_dir" >"$primary_log" 2>&1; then
        cat "$primary_log" >>"$LOG_FILE"
        rm -f -- "$primary_log"
        return 0
    fi
    cat "$primary_log" >>"$LOG_FILE"
    if ! grep -Eqi 'Temporary failure resolving|Could not resolve|Name or service not known|Connection timed out|Could not connect|Network is unreachable|Failed to fetch|apk|returned a non-zero code: 124' "$primary_log"; then
        rm -f -- "$primary_log"
        return 1
    fi
    rm -f -- "$primary_log"
    log_warn "Docker build не получил DNS через сеть VPS; повтор с резервными DNS Яндекса"
    fallback_log="$(mktemp)" || return 1
    if timeout -k 15s "${DOCKER_BUILD_TIMEOUT_SECONDS}s" docker build --network default \
        --build-arg CSQTT_BUILD_DNS_PRIMARY=77.88.8.8 \
        --build-arg CSQTT_BUILD_DNS_SECONDARY=77.88.8.1 \
        -t "$image" "$context_dir" >"$fallback_log" 2>&1; then
        cat "$fallback_log" >>"$LOG_FILE"
        rm -f -- "$fallback_log"
        log_info "Docker-образ собран через резервные DNS Яндекса"
        return 0
    fi
    cat "$fallback_log" >>"$LOG_FILE"
    rm -f -- "$fallback_log"
    return 1
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
    write_tun_recovery_helper "$context_dir/tun-recover.sh" || \
        die "Не удалось подготовить Docker TUN recovery helper" "$EXIT_PREFLIGHT_FAILED"
    write_csqtt_dockerfile "$context_dir/Dockerfile"

    CSQTT_DOCKER_CANDIDATE_IMAGE="${CSQTT_DOCKER_IMAGE}-candidate-$$"
    if ! docker_build_candidate_image "$CSQTT_DOCKER_CANDIDATE_IMAGE" "$context_dir"; then
        tail -n 80 "$LOG_FILE" | sed 's/^/   >> /' >&2 || true
        die "Сборка Docker-образа CSQTT завершилась ошибкой" "$EXIT_PREFLIGHT_FAILED"
    fi
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
    install_docker_boot_prerequisite
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
    remove_all_csqtt_docker_containers
    assert_peer_port_is_available
    remove_csqtt_tun_interface || die "Не удалось освободить TUN-интерфейс $CSQTT_IFACE перед запуском Docker"

    docker run -d \
        --name "$CSQTT_DOCKER_CONTAINER" \
        --label com.csqtt.managed=true \
        --label com.csqtt.component=server \
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
        --mount "type=bind,src=${CSQTT_RUNTIME_DIR},dst=${CSQTT_RUNTIME_DIR}" \
        --mount "type=bind,src=/run/xtables.lock,dst=/run/xtables.lock" \
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
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
EnvironmentFile=-${CSQTT_ENV_FILE}
Environment=CSQTT_SERVICE_MANAGER=systemd
ExecStartPre=/usr/local/lib/csqtt/network-up.sh
ExecStartPre=/usr/local/lib/csqtt/tun-recover.sh
ExecStart=/usr/local/bin/csqtt --listen 0.0.0.0:${PEER_PORT} --web-port ${WEB_PORT} --config-dir ${CSQTT_CONFIG_DIR}
Restart=on-failure
RestartSec=3
KillMode=control-group
TimeoutStartSec=30
TimeoutStopSec=5

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

    remove_all_csqtt_docker_containers
    if command -v docker >/dev/null 2>&1; then
        timeout 5 docker image rm "$CSQTT_DOCKER_IMAGE" >/dev/null 2>&1 || true
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now "$CSQTT_LE_TIMER" >/dev/null 2>&1 || true
        systemctl stop "$CSQTT_LE_SERVICE" --no-block >/dev/null 2>&1 || true
        stop_all_running_csqtt_systemd_units
        systemctl disable "$CSQTT_DOCKER_PREREQ_SERVICE" >/dev/null 2>&1 || true
    fi
    force_stop_csqtt_processes || log_warn "Не все процессы CSQTT завершились до удаления runtime"
    remove_all_csqtt_systemd_units
    rm -f "/etc/systemd/system/${CSQTT_DOCKER_PREREQ_SERVICE}"
    rm -f "/etc/systemd/system/docker.service.requires/${CSQTT_DOCKER_PREREQ_SERVICE}"
    rm -f "/etc/systemd/system/docker.service.wants/${CSQTT_DOCKER_PREREQ_SERVICE}"
    rm -f "/etc/systemd/system/${CSQTT_LE_SERVICE}" "/etc/systemd/system/${CSQTT_LE_TIMER}"
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true

    cleanup_legacy_proxy_interfaces
    remove_csqtt_tun_interface || log_warn "Не удалось удалить TUN-интерфейс $CSQTT_IFACE во время uninstall"
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
        install|--install|-i)
            DEPLOY_PHASE="validation"
            case "$DEPLOY_MODE" in
                systemd|docker) ;;
                *) die "CSQTT_DEPLOY_MODE должен быть systemd или docker" ;;
            esac
            validate_port "CSQTT_PEER_PORT" "$PEER_PORT"
            validate_port "CSQTT_SSH_PORT" "$SSH_PORT"
            validate_port "CSQTT_WEB_PORT" "$WEB_PORT"
            validate_positive_seconds "CSQTT_DOCKER_BUILD_TIMEOUT_SECONDS" "$DOCKER_BUILD_TIMEOUT_SECONDS"
            validate_distinct_network_ports

            local total_started=$SECONDS
            detect_os
            run_timed "зависимости" install_prerequisites
            require_runtime_tools
            if [ "$DEPLOY_MODE" = "docker" ]; then
                prog 0.12 "Docker..."
                run_timed "Docker" ensure_docker
            fi
            run_timed "sysctl" setup_sysctl

            run_timed "проверка upload" prepare_uploaded_release
            if [ "$DEPLOY_MODE" = "docker" ]; then
                run_timed "Docker preflight" prepare_docker_candidate "$UPLOAD_BINARY"
            fi
            DEPLOY_PHASE="cutover"
            run_timed "переключение runtime" csqtt_cleanup
            run_timed "preflight" run_platform_preflight
            detect_firewall
            run_timed "NAT/firewall" setup_nat_and_firewall
            install_network_helper
            setup_csqtt_environment
            run_timed "Let’s Encrypt" setup_letsencrypt_ip_tls
            DEPLOY_PHASE="activation"
            run_timed "бинарник" setup_csqtt_binary
            run_timed "принудительная остановка" force_stop_csqtt_processes
            if [ "$DEPLOY_MODE" = "docker" ]; then
                run_timed "Docker activation" setup_csqtt_docker
            else
                run_timed "systemd unit" setup_csqtt_service
            fi
            run_timed "запуск" start_csqtt
            log_info "Общее время deploy.sh: $((SECONDS - total_started))с"
            ;;
        *) die "Неизвестная команда установщика: $action" ;;
    esac
}

main "$@"
