#!/usr/bin/env bash
set -u -o pipefail

PEER_PORT="${CSQTT_PEER_PORT:-46000}"
WEB_PORT="${CSQTT_WEB_PORT:-46002}"
CSQTT_IFACE="${CSQTT_IFACE:-csqtt1}"
CSQTT_DIR="${CSQTT_CONFIG_DIR:-/etc/csqtt}"

if [ "$(id -u)" -ne 0 ]; then
    printf 'Run as root: sudo bash %s\n' "$0" >&2
    exit 1
fi

section() {
    printf '\n========== %s ==========' "$1"
    printf '\n'
}

redact() {
    sed -E \
        -e 's/((password|token|secret|authorization|cookie|api[_-]?key)[[:space:]]*[:=][[:space:]]*)[^[:space:];,]+/\1<redacted>/Ig' \
        -e 's/(--password[[:space:]]+)[^[:space:]]+/\1<redacted>/g' \
        -e 's#(csqtt://)[^@[:space:]]+@#\1<redacted>@#g'
}

safe() {
    "$@" 2>&1 || true
}

service_pids() {
    systemctl show --value -p MainPID csqtt.service 2>/dev/null | awk '$1 ~ /^[0-9]+$/ && $1 > 1 { print $1 }'
    pgrep -x csqtt 2>/dev/null || true
}

section 'timestamp and host'
safe date --iso-8601=seconds
safe hostnamectl
safe uname -a
safe uptime

section 'systemd state'
safe systemctl is-active csqtt.service
safe systemctl is-enabled csqtt.service
safe systemctl show csqtt.service \
    -p LoadState -p ActiveState -p SubState -p Result -p MainPID -p ControlPID \
    -p NRestarts -p ExecMainCode -p ExecMainStatus -p RestartUSec -p Restart \
    -p FragmentPath -p DropInPaths -p ControlGroup -p ExecStart -p ExecStartPre \
    -p EnvironmentFiles
safe systemctl status csqtt.service --no-pager --full

section 'unit definition'
safe systemctl cat csqtt.service

section 'other CSQTT systemd units'
safe systemctl list-units --all --type=service --no-legend --plain | awk 'tolower($0) ~ /csqtt/'
safe systemctl list-unit-files --no-legend | awk 'tolower($0) ~ /csqtt/'
safe find /etc/systemd/system /lib/systemd/system -type f -name '*.service' -print0 2>/dev/null | xargs -0r grep -lE '/usr/local/bin/csqtt|csqtt' 2>/dev/null

section 'CSQTT processes and owners'
for pid in $(service_pids | sort -un); do
    [ -r "/proc/$pid/status" ] || continue
    printf '%s\n' "PID=$pid"
    safe ps -p "$pid" -o pid,ppid,user,lstart,etime,stat,comm,args
    printf 'exe='
    readlink "/proc/$pid/exe" 2>/dev/null || true
    printf 'cgroup:\n'
    safe cat "/proc/$pid/cgroup"
    printf 'parent:\n'
    parent="$(awk '/^PPid:/ {print $2}' "/proc/$pid/status" 2>/dev/null || true)"
    if [ -n "$parent" ] && [ "$parent" -gt 1 ] 2>/dev/null; then
        safe ps -p "$parent" -o pid,ppid,user,lstart,etime,stat,comm,args
    fi
done | redact

section 'CSQTT executable and runtime files'
safe ls -l /usr/local/bin/csqtt /usr/local/lib/csqtt 2>/dev/null
safe sha256sum /usr/local/bin/csqtt 2>/dev/null
safe file /usr/local/bin/csqtt 2>/dev/null
safe find "$CSQTT_DIR" -maxdepth 2 -type f -printf '%M %u:%g %s bytes %TY-%Tm-%TdT%TH:%TM:%TS %p\n' 2>/dev/null | sort
safe ls -ld /run/csqtt "$CSQTT_DIR" 2>/dev/null

section 'database integrity without reading records'
if command -v sqlite3 >/dev/null 2>&1 && [ -f "$CSQTT_DIR/csqtt.db" ]; then
    safe sqlite3 "$CSQTT_DIR/csqtt.db" 'PRAGMA quick_check; SELECT name FROM sqlite_master WHERE type IN ("table", "index") ORDER BY type, name;'
else
    printf 'sqlite3 or %s/csqtt.db is unavailable\n' "$CSQTT_DIR"
fi

section 'listening sockets'
safe ss -H -lunp "sport = :$PEER_PORT"
safe ss -H -ltnp "sport = :$WEB_PORT"
safe ss -H -uanp | grep -E "(:$PEER_PORT|csqtt)" || true

section 'TUN and routing'
safe ls -l /dev/net/tun
safe ip -d link show "$CSQTT_IFACE"
safe ip -br address show "$CSQTT_IFACE"
safe ip -s link show "$CSQTT_IFACE"
safe ip route show table main
safe ip rule show
safe sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter

section 'CSQTT firewall rules'
if command -v iptables-save >/dev/null 2>&1; then
    safe iptables-save | grep -E 'CSQTT|10\.66\.67\.|46000|46002' || true
fi
if command -v nft >/dev/null 2>&1; then
    safe nft list ruleset | grep -Ei 'csqtt|10\.66\.67\.|46000|46002' || true
fi

section 'Docker and scheduled restart sources'
if command -v docker >/dev/null 2>&1; then
    safe docker ps -a --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}}' | grep -i csqtt || true
fi
safe find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron -type f -print0 2>/dev/null | xargs -0r grep -lEi 'csqtt|/usr/local/bin/csqtt' 2>/dev/null

section 'CSQTT journal, current boot'
safe journalctl -u csqtt.service -b -n 300 --no-pager -o short-iso | redact

section 'all current-boot CSQTT related journal lines'
safe journalctl -b --no-pager -o short-iso | grep -Ei 'csqtt|tun-recover|network-up' | tail -n 300 | redact

section 'result'
printf 'Report complete. No service, firewall, database, or configuration was modified.\n'
