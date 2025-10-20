#!/usr/bin/env bash
# WireGuard quick client setup for Ubuntu (IPv4 only)
# Supports --mode full|split for routing configuration.

set -euo pipefail

# ---------- Defaults ----------
WG_IFACE=""
WG_ADDRESS=""
SERVER_ENDPOINT=""
SERVER_PUBKEY=""
WG_SUBNET=""
MODE="split"
KEEPALIVE=25

# ---------- Helpers ----------
GetErrorMark()   { printf "\e[31m[-]\e[0m"; }
GetSuccessMark() { printf "\e[32m[+]\e[0m"; }

Usage() {
  cat <<EOF
Usage: sudo $0 --wg-iface <wg0|...> --address <CIDR> --endpoint <host:port> --server-pubkey <base64> --mode <full|split> [--subnet <CIDR>] [--keepalive <25>]

Required:
  --wg-iface        WireGuard interface name (e.g. wg0)
  --address         client address inside VPN (CIDR), e.g. 10.0.0.2/32
  --endpoint        server endpoint in form host:port (e.g. 192.168.1.1:51820)
  --server-pubkey   server WireGuard public key
  --mode            routing mode: "full" (all traffic via VPN) or "split" (only VPN subnet)
  --subnet          VPN subnet (CIDR, required for --mode split, e.g. 10.0.0.0/24)

Optional:
  --keepalive      PersistentKeepalive seconds; default: 25

Examples:
  sudo $0 --wg-iface=wg0 --address=10.0.0.2/32 --endpoint=203.0.113.5:51820 --server-pubkey=SOME_KEY= --mode=full
  sudo $0 --wg-iface=wg0 --address=10.0.0.2/32 --endpoint 192.168.1.1:51820 --server-pubkey=SOME_KEY --mode=split --subnet=10.0.0.0/24
EOF
}

# ---------- Functions ----------
RequireRoot() {
  if [[ $EUID -ne 0 ]]; then
    echo "$(GetErrorMark) please run as root"
    exit 1
  fi
}

EnsureDeps() {
  if ! command -v ip &>/dev/null; then
    echo "$(GetErrorMark) 'ip' command is required (install iproute2)"
    exit 1
  fi
  if ! command -v python3 &>/dev/null; then
    echo "$(GetErrorMark) python3 is required but not installed"
    exit 1
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y wireguard wireguard-tools
  if ! command -v wg &>/dev/null || ! command -v wg-quick &>/dev/null; then
    echo "$(GetErrorMark) WireGuard tools not found after install"
    exit 1
  fi
}

ValidateInputs() {
  if [[ -z "${WG_IFACE}" ]]; then
    echo "$(GetErrorMark) missing required argument: --wg-iface"
    Usage
    exit 1
  fi
  if [[ -z "${WG_ADDRESS}" ]]; then
    echo "$(GetErrorMark) missing required argument: --address"
    Usage
    exit 1
  fi
  if [[ -z "${SERVER_ENDPOINT}" ]]; then
    echo "$(GetErrorMark) missing required argument: --endpoint";
    Usage;
    exit
  fi
  if [[ -z "${SERVER_PUBKEY}" ]]; then
    echo "$(GetErrorMark) missing required argument: --server-pubkey"
    Usage
    exit 1
  fi

  if [[ "${MODE}" != "full" && "${MODE}" != "split" ]]; then
    echo "$(GetErrorMark) --mode must be either 'full' or 'split'"
    Usage
    exit 1
  fi
  if [[ "${MODE}" == "split" && -z "${WG_SUBNET}" ]]; then
    echo "$(GetErrorMark) --subnet is required when --mode split"
    Usage
    exit 1
  fi

  if ! [[ "${SERVER_ENDPOINT}" =~ ^[^:]+:[0-9]{1,5}$ ]]; then
    echo "$(GetErrorMark) --endpoint must be in form host:port"
    Usage
    exit 1
  fi
  local port="${SERVER_ENDPOINT##*:}"
  if (( port < 1 || port > 65535 )); then
    echo "$(GetErrorMark) endpoint port out of range: ${port}"
    Usage
    exit 1
  fi

  if ! python3 - <<PY "${WG_ADDRESS}" >/dev/null 2>&1; then
import sys, ipaddress
ipaddress.ip_interface(sys.argv[1])
PY
  then
    echo "$(GetErrorMark) invalid --address CIDR: ${WG_ADDRESS}"
    Usage
    exit 1
  fi

  if [[ "${MODE}" == "split" ]]; then
    if ! python3 - <<PY "${WG_SUBNET}" >/dev/null 2>&1; then
import sys, ipaddress
ipaddress.ip_network(sys.argv[1], strict=True)
PY
    then
      echo "$(GetErrorMark) invalid --subnet CIDR: ${WG_SUBNET}"
      Usage
      exit 1
    fi
  fi
}

CreateKeys() {
  install -d -m 0700 /etc/wireguard
  if [[ ! -f /etc/wireguard/privatekey ]]; then
    umask 077
    wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
    chmod 600 /etc/wireguard/privatekey
    echo "$(GetSuccessMark) created wg keys successfully"
  else
    chmod 600 /etc/wireguard/privatekey >/dev/null 2>&1 || true
    echo "$(GetSuccessMark) wg keys already exist, skipping"
  fi
}

CreateClientConfig() {
  local cfg="/etc/wireguard/${WG_IFACE}.conf"
  local allowed_ips
  if [[ "${MODE}" == "full" ]]; then
    allowed_ips="0.0.0.0/0"
  else
    allowed_ips="${WG_SUBNET}"
  fi

  cat > "${cfg}" <<EOF
[Interface]
Address = ${WG_ADDRESS}
PrivateKey = $(cat /etc/wireguard/privatekey)
SaveConfig = true

[Peer]
PublicKey = ${SERVER_PUBKEY}
AllowedIPs = ${allowed_ips}
Endpoint = ${SERVER_ENDPOINT}
PersistentKeepalive = ${KEEPALIVE}
EOF
  chmod 600 "${cfg}"
  echo "$(GetSuccessMark) created wg client config: ${cfg}"
}

StartWireGuard() {
  wg-quick down "${WG_IFACE}" >/dev/null 2>&1 || true
  wg-quick up "${WG_IFACE}"
  systemctl enable --now "wg-quick@${WG_IFACE}.service" >/dev/null
  echo "$(GetSuccessMark) interface ${WG_IFACE} is up and enabled at boot"
}

# ---------- Parse named args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --wg-iface=*)      WG_IFACE="${1#*=}"; shift ;;
    --wg-iface)        WG_IFACE="${2:?}"; shift 2 ;;
    --address=*)       WG_ADDRESS="${1#*=}"; shift ;;
    --address)         WG_ADDRESS="${2:?}"; shift 2 ;;
    --endpoint=*)      SERVER_ENDPOINT="${1#*=}"; shift ;;
    --endpoint)        SERVER_ENDPOINT="${2:?}"; shift 2 ;;
    --server-pubkey=*) SERVER_PUBKEY="${1#*=}"; shift ;;
    --server-pubkey)   SERVER_PUBKEY="${2:?}"; shift 2 ;;
    --mode=*)          MODE="${1#*=}"; shift ;;
    --mode)            MODE="${2:?}"; shift 2 ;;
    --subnet=*)        WG_SUBNET="${1#*=}"; shift ;;
    --subnet)          WG_SUBNET="${2:?}"; shift 2 ;;
    --keepalive=*)     KEEPALIVE="${1#*=}"; shift ;;
    --keepalive)       KEEPALIVE="${2:?}"; shift 2 ;;
    -h|--help)         Usage; exit 0 ;;
    *) echo "$(GetErrorMark) unknown argument: $1"; Usage; exit 1 ;;
  esac
done

# ---------- Flow ----------
RequireRoot
EnsureDeps
ValidateInputs
CreateKeys
CreateClientConfig
StartWireGuard
ShowSummary

echo
echo "$(GetSuccessMark) WireGuard client setup successfully done"