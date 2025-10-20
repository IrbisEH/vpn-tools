#!/usr/bin/env bash
# WireGuard quick server setup for Ubuntu (IPv4 only)

set -euo pipefail

# ---------- Defaults ----------
WAN_IFACE=""
WG_IFACE=""
WG_SUBNET=""
WG_PORT=51820

# ---------- Helpers ----------
function GetErrorMark() { printf "\e[31m[-]\e[0m"; }
function GetSuccessMark() { printf "\e[32m[+]\e[0m"; }

function Usage() {
	cat <<EOF
Usage: sudo $0 --iface <external-iface> [--wg-iface <wg0|...>] [--subnet <CIDR>] [--port <51820>]

Required:
 --iface        external interface name (WAN interface)
 --wg-iface     WireGuard interface name (e.g. wg0)
 --subnet       vpn-subnet with CIDR (e.g. 10.6.0.0/24)

Optional:
  --port        WireGuard port (by default: 51820)

Examples:
  sudo $0 --iface=ens3
  sudo $0 --iface=eth0 --wg-iface=wg1 --subnet=10.8.0.0/24 --port=51821
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

function EnsureDeps() {
  if ! command -v ip &>/dev/null; then
    echo "$(GetErrorMark) 'ip' command is required (install iproute2)"
    exit 1
  fi
  if ! command -v python3 &>/dev/null; then
    echo "$(GetErrorMark) python3 is required but not installed"
    exit 1
  fi
  if ! python3 -c "import ipaddress" &>/dev/null; then
    echo "$(GetErrorMark) missing python module: 'ipaddress'"
    exit 1
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y wireguard wireguard-tools iptables
  if ! command -v wg &>/dev/null || ! command -v wg-quick &>/dev/null; then
    echo "$(GetErrorMark) WireGuard tools not found after install"
    exit 1
  fi
}

function CreateKeys() {
  install -d -m 0700 /etc/wireguard
  cd /etc/wireguard/
  if [[ ! -f privatekey ]]; then
      umask 077
    wg genkey | tee privatekey | wg pubkey > publickey
    echo "$(GetSuccessMark) created wg keys successfully"
  else
    chmod 600 /etc/wireguard/privatekey >/dev/null 2>&1 || true
    echo "$(GetSuccessMark) wg keys already exist, skipping"
  fi
}

function CreateServerConfig() {
  local cfg="/etc/wireguard/${WG_IFACE}.conf"
  local addr="$(GetFirstHost "${WG_SUBNET}")"
  local server_ip="${addr%/*}"
  local prefix="${addr#*/}"

  cat > "${cfg}" <<EOF
[Interface]
Address = ${server_ip}/${prefix}
ListenPort = ${WG_PORT}
PrivateKey = $(cat /etc/wireguard/privatekey)
SaveConfig = true

PostUp   = iptables -A INPUT -i ${WAN_IFACE} -p udp --dport ${WG_PORT} -j ACCEPT; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -o ${WAN_IFACE} -j MASQUERADE
PostDown = iptables -D INPUT -i ${WAN_IFACE} -p udp --dport ${WG_PORT} -j ACCEPT; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -o ${WAN_IFACE} -j MASQUERADE
EOF
  chmod 600 "${cfg}"
  echo "$(GetSuccessMark) created wg server config successfully"
}

function EnableIpforward() {
  install -d -m 0755 /etc/sysctl.d
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  printf "net.ipv4.ip_forward=1\n" > /etc/sysctl.d/99-wireguard.conf
  # if need Ipv6:
  # printf "net.ipv6.conf.all.forwarding=1\n" >> /etc/sysctl.d/99-wireguard.conf
  sysctl --system >/dev/null
  echo "$(GetSuccessMark) enable ip forward"
}

function SetupFirewall() {
  if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow "${WG_PORT}"/udp || true
    echo "$(GetSuccessMark) UFW: allowed ${WG_PORT}/udp"
  fi
}

StartWireGuard() {
  # bring up once and enable autostart
  wg-quick down "${WG_IFACE}" >/dev/null 2>&1 || true
  wg-quick up "${WG_IFACE}"
  systemctl enable --now "wg-quick@${WG_IFACE}.service" >/dev/null
  echo "$(GetSuccessMark) interface ${WG_IFACE} is up and enabled at boot"
}

# ---------- Parse named args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface=*)    WAN_IFACE="${1#*=}"; shift 1 ;;
    --wg-iface=*) WG_IFACE="${1#*=}"; shift 1 ;;
    --port=*)     WG_PORT="${1#*=}"; shift 1 ;;
    --subnet=*)   WG_SUBNET="${1#*=}"; shift 1 ;;
    -h|--help) Usage; exit 0 ;;
    *) echo "$(GetErrorMark) unknown argument: $1"; Usage; exit 1 ;;
  esac
done

# ---------- Basic validation --------
RequireRoot
EnsureDeps

if [[ -z "${WAN_IFACE}" ]]; then
  echo "$(GetErrorMark) missing required argument: --iface";
  Usage
  exit 1
fi
if [[ -z "${WG_IFACE}" ]]; then
  echo "$(GetErrorMark) missing required argument: --wg-iface";
  Usage;
  exit 1
fi
if [[ -z "${WG_SUBNET}" ]]; then
  echo "$(GetErrorMark) missing required argument: --subnet";
  Usage;
  exit 1
fi
if ! [[ "${WG_PORT}" =~ ^[0-9]{1,5}$ ]] || (( WG_PORT < 1 || WG_PORT > 65535 )); then
  echo "$(GetErrorMark) invalid --port: ${WG_PORT}";
  exit 1
fi

# Validate subnet via Python to give nice error early
if ! python3 - <<PY "${WG_SUBNET}" >/dev/null 2>&1; then
import sys, ipaddress
ipaddress.ip_network(sys.argv[1], strict=True)
PY
then
  echo "$(GetErrorMark) invalid --subnet CIDR: ${WG_SUBNET}"; exit 1
fi

if ! ip link show "${WAN_IFACE}" &>/dev/null; then
  echo "$(GetErrorMark) interface ${WAN_IFACE} not found. Check --iface"
  exit 1
fi

# ---------- Main flow ----------
CreateKeys
CreateServerConfig
EnableIpforward
SetupFirewall
StartWireGuard

echo
echo "$(GetSuccessMark) WireGuard server setup successfully done"
echo " Server address: $(GetFirstHost "${WG_SUBNET}")  (iface: ${WG_IFACE}, port: ${WG_PORT}/udp)"
echo " Add peers: wg set ${WG_IFACE} peer <pubkey> allowed-ips <client_ip/32> && wg-quick save ${WG_IFACE}"