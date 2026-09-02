#!/usr/bin/env bash
set -u

mode="${1:-report}"
duration="${2:-25}"

if [[ "$mode" != "report" && "$mode" != "capture" ]]; then
    printf 'Usage: %s [report|capture] [seconds]\n' "$0" >&2
    exit 2
fi

if ! [[ "$duration" =~ ^[1-9][0-9]*$ ]] || (( duration > 300 )); then
    printf 'Capture duration must be an integer between 1 and 300 seconds\n' >&2
    exit 2
fi

section() {
    printf '\n========== %s ==========' "$1"
    printf '\n'
}

run() {
    printf '\n$'
    printf ' %q' "$@"
    printf '\n'
    "$@" 2>&1
    local status=$?
    printf '[exit=%s]\n' "$status"
}

run_shell() {
    printf '\n$ %s\n' "$1"
    bash -o pipefail -c "$1" 2>&1
    local status=$?
    printf '[exit=%s]\n' "$status"
}

have() {
    command -v "$1" >/dev/null 2>&1
}

if (( EUID != 0 )); then
    printf 'Run this report as root: sudo bash %s %s\n' "$0" "$mode" >&2
    exit 1
fi

section "CSQTT network report"
printf 'UTC: %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
printf 'Host: %s\n' "$(hostname -f 2>/dev/null || hostname)"
printf 'Mode: %s\n' "$mode"

if [[ "$mode" == "capture" ]]; then
    section "UDP capture"
    if have tcpdump; then
        printf 'Start the CSQTT client now. Capture ends after %s seconds.\n' "$duration"
        run timeout "${duration}s" tcpdump -ni any -nn -tttt -vv 'udp port 46000'
    else
        printf 'tcpdump is not installed. Install it with: apt-get update && apt-get install -y tcpdump\n'
    fi
    exit 0
fi

section "Operating system"
run uname -a
[[ -r /etc/os-release ]] && run cat /etc/os-release
run uptime

section "CSQTT service"
run systemctl status csqtt --no-pager --full
run systemctl show csqtt -p ActiveState -p SubState -p Result -p MainPID -p NRestarts -p ExecMainCode -p ExecMainStatus -p RestartUSec
run systemctl cat csqtt
run_shell "journalctl -u csqtt -b -n 200 --no-pager | sed -E 's/(\\[INIT\\] generated (main|web) password: ).*/\\1[REDACTED]/'"
run ps -eo pid,ppid,user,stat,etimes,cmd --forest

section "Listening sockets"
run ss -lunp
run ss -ltnp

section "Interfaces and routes"
run ip -br link
run ip -br address
run ip -d link show csqtt1
run ip address show dev csqtt1
run ip tuntap show
run ip route show table all
run ip rule show
run ip route get 1.1.1.1
run ls -l /dev/net/tun

section "Kernel networking"
run sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.core.rmem_max net.core.wmem_max net.netfilter.nf_conntrack_max
wan_iface="$(ip -o -4 route show default 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}')"
if [[ -n "$wan_iface" ]]; then
    run sysctl "net.ipv4.conf.${wan_iface}.rp_filter"
fi
run sysctl net.ipv4.conf.csqtt1.rp_filter
have nstat && run nstat

section "Firewall"
have iptables-save && run iptables-save -c
have iptables && run iptables -w 2 -nvL
have iptables && run iptables -w 2 -t nat -nvL
have iptables && run iptables -w 2 -t mangle -nvL
have nft && run nft list ruleset
have ufw && run ufw status verbose
have firewall-cmd && run firewall-cmd --state
have firewall-cmd && run firewall-cmd --list-all

section "Runtime files"
run ls -ld /etc/csqtt /run/csqtt /usr/local/lib/csqtt
run find /etc/csqtt -maxdepth 1 -mindepth 1 -printf '%M %u:%g %s %f\n'
have docker && run docker ps -a --no-trunc

section "Report complete"
