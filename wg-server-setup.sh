#!/usr/bin/env bash
# WireGuard quick server setup for Ubuntu (IPv4 only)
#   internet  - clients isolated from each other, NAT to Internet via WAN
#   intranet  - clients can talk to each other, no Internet via VPN

set -euo pipefail

# ---------- Defaults ----------
WG_IFACE=""
WG_SUBNET=""
MODE=""
WAN_IFACE=""
WG_PORT=51820

# ---------- Helpers ----------
function GetMark() { printf "\e[33m[>]\e[0m"; }

function GetErrorMark() { printf "\e[31m[-]\e[0m"; }

function GetSuccessMark() { printf "\e[32m[+]\e[0m"; }

function GetWarningMark() { printf "\e[33m[!]\e[0m"; }

function Usage() {
	cat <<EOF
Usage: sudo $0 --iface=<external-iface> --wg-iface=<wg0|...> --subnet=<CIDR> --mode=<internet|intranet> [--port=<51820>]

Required:
  --iface        external interface name (WAN), required when --mode=internet
  --wg-iface     WireGuard interface name (e.g. wg0)
  --subnet       VPN subnet with prefix (e.g. 10.6.0.0/24)
  --mode        'internet' (NAT, clients isolated) | 'intranet' (no NAT, clients can talk)

Optional:
  --port        WireGuard port (by default: 51820)

Examples:
  # Internet via VPN, clients isolated
  sudo $0 --iface=eth0 --wg-iface=wg0 --subnet=10.0.0.0/24 --mode=internet

  # No Internet via VPN, internal mesh only
  sudo $0 --iface=eth0 --wg-iface=wg0 --subnet=10.0.0.0/24 --mode=intranet --port=51821
EOF
}

function GetFirstHost() {
  local cidr="$1"
  python3 - "${cidr}" <<'PY'
import sys, ipaddress
cidr = sys.argv[1]
net = ipaddress.ip_network(cidr, strict=True)
first_host = net[1] if net.num_addresses >= 4 else net.network_address
print(f'{first_host}/{net.prefixlen}')
PY
}

# ---------- Functions ---------
function RequireRoot() {
  if [[ $EUID -ne 0 ]]; then
    echo "$(GetErrorMark) please run as root"
    exit 1
  fi
}

function CheckDeps() {
  if ! command -v ip &>/dev/null; then
    echo "$(GetErrorMark) 'ip' command is required"; exit 1
  fi
  if ! command -v python3 &>/dev/null; then
    echo "$(GetErrorMark) python3 is required but not installed"; exit 1
  fi
  if ! python3 -c "import ipaddress" &>/dev/null; then
    echo "$(GetErrorMark) missing python module: 'ipaddress'"; exit 1
  fi
}

function InstallDeps() {
  echo "$(GetMark) starting dependency installation..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y wireguard wireguard-tools iptables
  if ! command -v wg &>/dev/null || ! command -v wg-quick &>/dev/null; then
    echo "$(GetErrorMark) WireGuard tools not found after install"; exit 1
  fi
}

function Validate() {
  if [[ -z "${WAN_IFACE}" ]]; then
    echo "$(GetErrorMark) missing required argument: --iface"; Usage; exit 1
  fi
  if [[ -z "${WG_IFACE}" ]]; then
    echo "$(GetErrorMark) missing required argument: --wg-iface"; Usage; exit 1
  fi
  if [[ -z "${WG_SUBNET}" ]]; then
    echo "$(GetErrorMark) missing required argument: --subnet"; Usage; exit 1
  fi
  if [[ -z "${MODE}" ]]; then
    echo "$(GetErrorMark) missing required argument: --mode"; Usage; exit 1
  fi
  if ! [[ "${WG_PORT}" =~ ^[0-9]{1,5}$ ]] || (( WG_PORT < 1 || WG_PORT > 65535 )); then
    echo "$(GetErrorMark) invalid --port: ${WG_PORT}"; Usage; exit 1
  fi

  # Validate subnet via Python to give nice error early
  if ! python3 - "${WG_SUBNET}" &>/dev/null <<PY
import sys, ipaddress
ipaddress.ip_network(sys.argv[1], strict=True)
PY
  then
    echo "$(GetErrorMark) invalid --subnet CIDR: ${WG_SUBNET}"; exit 1
  fi

  # Only check WAN interface when needed
  if [[ "${MODE}" == "internet" ]]; then
    if ! ip link show "${WAN_IFACE}" &>/dev/null; then
      echo "$(GetErrorMark) interface ${WAN_IFACE} not found. Check --iface"; exit 1
    fi
  fi
}

function CreateKeys() {
  install -d -m 0700 /etc/wireguard

  if [[ ! -f /etc/wireguard/privatekey ]]; then
    umask 077
    wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
    chmod 600 /etc/wireguard/privatekey
    echo "$(GetSuccessMark) created wg keys successfully"
  else
    chmod 600 /etc/wireguard/privatekey >/dev/null 2>&1 || true
    echo "$(GetWarningMark) wg keys already exist, skipping"
  fi
}

function CreateServerConfig() {
  local cfg="/etc/wireguard/${WG_IFACE}.conf"
  local addr="$(GetFirstHost "${WG_SUBNET}")"
  local server_ip="${addr%/*}"
  local prefix="${addr#*/}"


  local postup postdown

  if [[ "${MODE}" == "internet" ]]; then
    # Internet mode: open UDP port; isolate clients (wg->wg DROP); allow wg->WAN; allow return traffic; enable NAT
    postup="iptables -A INPUT -i ${WAN_IFACE} -p udp --dport ${WG_PORT} -j ACCEPT; \
            iptables -A FORWARD -i %i -o %i -j DROP; \
            iptables -A FORWARD -i %i -o ${WAN_IFACE} -j ACCEPT; \
            iptables -A FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; \
            iptables -t nat -A POSTROUTING -o ${WAN_IFACE} -j MASQUERADE"

    postdown="iptables -D INPUT -i ${WAN_IFACE} -p udp --dport ${WG_PORT} -j ACCEPT; \
              iptables -D FORWARD -i %i -o %i -j DROP; \
              iptables -D FORWARD -i %i -o ${WAN_IFACE} -j ACCEPT; \
              iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; \
              iptables -t nat -D POSTROUTING -o ${WAN_IFACE} -j MASQUERADE"
  else
    # Intranet mode: open UDP port; allow wg<->wg communication; allow return traffic; no NAT
    postup="iptables -A INPUT -i ${WAN_IFACE} -p udp --dport ${WG_PORT} -j ACCEPT; \
            iptables -A FORWARD -i %i -o %i -j ACCEPT; \
            iptables -A FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"

    postdown="iptables -D INPUT -i ${WAN_IFACE} -p udp --dport ${WG_PORT} -j ACCEPT; \
              iptables -D FORWARD -i %i -o %i -j ACCEPT; \
              iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
  fi

  cat > "${cfg}" <<EOF
[Interface]
Address = ${server_ip}/${prefix}
ListenPort = ${WG_PORT}
PrivateKey = $(cat /etc/wireguard/privatekey)
SaveConfig = true

# Auto rules for ${MODE} mode
PostUp   = ${postup}
PostDown = ${postdown}
EOF
  chmod 600 "${cfg}"
  echo "$(GetSuccessMark) created wg server config (${MODE} mode)"
}

function EnableIpforward() {
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  install -d -m 0755 /etc/sysctl.d
  printf "net.ipv4.ip_forward=1\n" > /etc/sysctl.d/99-wireguard.conf
  # if need Ipv6:
  # printf "net.ipv6.conf.all.forwarding=1\n" >> /etc/sysctl.d/99-wireguard.conf
  sysctl --system >/dev/null
  echo "$(GetSuccessMark) enabled ip forward"
}

function SetupFirewall() {
  if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    ufw --quiet allow "${WG_PORT}"/udp || true
    echo "$(GetSuccessMark) UFW: allowed ${WG_PORT}/udp"
  fi
}

function StartWireGuard() {
  local log="/var/log/wg-quick-${WG_IFACE}.log"
  : > "${log}"

  echo "$(GetMark) bringing up ${WG_IFACE}..."

  wg-quick down "${WG_IFACE}" &>/dev/null || true

  if ! wg-quick up "${WG_IFACE}" &>>"${log}"; then
    echo "$(GetErrorMark) failed to bring up ${WG_IFACE}"
    echo "→ See log: ${log}"
    echo "→ Or check: systemctl status wg-quick@${WG_IFACE}.service"
    tail -n 10 "${log}" | sed 's/^/  /'
    exit 1
  fi

  if ! systemctl enable --now "wg-quick@${WG_IFACE}.service" &>>"${log}"; then
    echo "$(GetWarningMark) service enabled, but not started cleanly (see ${log})"
  fi

  echo "$(GetSuccessMark) interface ${WG_IFACE} is up and enabled at boot"
}

# ---------- Parse named args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface=*)    WAN_IFACE="${1#*=}"; shift 1 ;;
    --wg-iface=*) WG_IFACE="${1#*=}"; shift 1 ;;
    --port=*)     WG_PORT="${1#*=}"; shift 1 ;;
    --subnet=*)   WG_SUBNET="${1#*=}"; shift 1 ;;
    --mode=*)     MODE="${1#*=}"; shift 1 ;;
    -h|--help) Usage; exit 0 ;;
    *) echo "$(GetErrorMark) unknown argument: $1"; Usage; exit 1 ;;
  esac
done

# ---------- Basic validation --------
RequireRoot
CheckDeps
Validate
InstallDeps

# ---------- Main flow ----------
CreateKeys
CreateServerConfig
EnableIpforward
SetupFirewall
StartWireGuard
echo "$(GetSuccessMark) WireGuard server setup successfully done"

echo
echo "Server address: $(GetFirstHost "${WG_SUBNET}")  (iface: ${WG_IFACE}, port: ${WG_PORT}/udp)"
echo -e "To add peers use command: \e[33mwg set ${WG_IFACE} peer <pubkey> allowed-ips <client_ip/32> && wg-quick save ${WG_IFACE}\e[0m"