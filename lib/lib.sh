#!/usr/bin/env bash

LOG_FILE="${LOG_FILE:-./setup.log}"

# ---------- Helpers ----------
log() {
  local level="${1:-info}"; shift
  local message="${*:-}"
  local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

  local color_reset="\e[0m"
  local color_info=""           # <-- no color
  local color_warn="\e[33m"     # yellow
  local color_error="\e[31m"    # red
  local color_success="\e[32m"  # green

  local color prefix

  case "$level" in
    info)     color="$color_info";    prefix=">"  ;;
    warn)     color="$color_warn";    prefix="!"  ;;
    error)    color="$color_error";   prefix="-"  ;;
    success)  color="$color_success"; prefix="+"  ;;
    *)        color="$color_reset";   prefix="?"  ;;
  esac

  if [[ -z "$color" ]]; then
    printf "%s %s %s\n" "[$prefix]" "$timestamp" "$message"
  else
    printf "%b%s%b %s %s\n" "$color" "[$prefix]" "$color_reset" "$timestamp" "$message"
  fi

  printf "%s %s %s\n" "[$prefix]" "$timestamp" "$message" >> "$LOG_FILE"
}

run() {
  local title="$1"; shift 1

  log info "$title"

  (
    set -euo pipefail
    "$@"
  ) >>"$LOG_FILE" 2>&1

  rc=$?

  if (( rc == 0 )); then
    log success "$title - done"
  else
    log error "$title - failed (rc=$rc)"
    return "$rc"
  fi
}

setup_logs() {
  local log_dir="$1"
  mkdir -p "$log_dir"
  LOG_FILE="$log_dir/vpn-tools.log"
  touch "$LOG_FILE"
}

make_tmp_copy() {
  local source="$1"

  local dir=$(dirname "$source")
  local name=$(basename "$source")
  local tmp=$(mktemp -p "$dir" ".$name.XXXXXX") || return 1

  if [[ -e "$source" ]]; then
    cp -a -- "$source" "$tmp" || { rm -f -- "$tmp"; return 1; }
  else
    : >"$tmp" || { rm -f -- "$tmp"; return 1; }
    chmod 0644 "$tmp"
  fi

  printf "%s\n" "$tmp"
}

# ---------- Functions ----------

enable_ufw() {
  ufw --force enable
  ufw allow ssh
  ufw reload
}

update_system() {
  DEBIAN_FRONTEND=noninteractive apt update -y
  DEBIAN_FRONTEND=noninteractive apt upgrade -y
}

install_wireguard() {
  DEBIAN_FRONTEND=noninteractive apt install -y wireguard
}

install_wstunnel() {
  latest="$(curl -sI https://github.com/erebe/wstunnel/releases/latest | tr -d '\r' | grep '^location:')" \
  && latest="${latest##*/v}" \
  && curl -fLo wstunnel.tar.gz "https://github.com/erebe/wstunnel/releases/download/v${latest}/wstunnel_${latest}_linux_amd64.tar.gz"
  tar -xzf wstunnel.tar.gz wstunnel
  chmod +x wstunnel
  mv wstunnel /usr/local/bin
  wstunnel --version || return 1
  setcap cap_net_bind_service=+ep /usr/local/bin/wstunnel
  useradd --system --shell /usr/sbin/nologin wstunnel || true
}

gen_secret() {
  local secret=$(LC_ALL=C tr -dc '[:alnum:]' < /dev/urandom | head -c 64)
  printf '%s\n' "$secret"
}

setup_forward() {
  local cidr="$1"
  local iface="$2"

  if [[ -z "$cidr" || -z "$iface" ]]; then
    echo "usage: setup_forward <CIDR> <IFACE>   e.g. setup_forward 10.10.0.0/24 eth0" >&2
    return 1
  fi

  echo -e "start setting core"
  enable_core_forward

  echo -e "start updating ufw"
  enable_ufw_forward

  echo -e "start updating nat"
  enable_nat_forward_rules "$cidr" "$iface"

  echo "start updating filter"
  enable_filter_forward_rule "$cidr" "$iface"


#  sudo ufw route allow in on eth1 out on eth0
#sudo ufw route allow in on eth0 out on eth1

}

enable_core_forward() {
  local conf="/etc/sysctl.d/99-wireguard.conf"
  local tmp="$(make_tmp_copy "$conf")"

  cat << 'EOF' > "$tmp"
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF

  mv -f -- "$tmp" "$conf"
  sysctl -p "$conf" || sysctl --system
}

enable_nat_forward_rules() {
  local cidr="$1"
  local iface="$2"

  local rules
  local conf="/etc/ufw/before.rules"
  local tmp=$(make_tmp_copy "$conf")

  read -r -d '' rules <<EOF || true
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s $cidr -o $iface -j MASQUERADE
COMMIT
EOF

  awk -v block="$rules" '
    BEGIN { inserted=0 }
    /^\*nat$/     { skip=1; next }
    skip && /^COMMIT$/ { skip=0; next }
    /^\*filter$/ && !inserted { print block; inserted=1 }
    { if (!skip) print }
    END { if (!inserted) print block }
  ' "$conf" >"$tmp"

  mv -f -- "$tmp" "$conf"
}

enable_filter_forward_rule() {
  local cidr="$1"
  local iface="$2"

  local rules
  local conf="/etc/ufw/before.rules"
  local tmp=$(make_tmp_copy "$conf")

  read -r -d '' rule <<EOF || true
-A ufw-before-forward -s $cidr -o $iface -j ACCEPT
EOF

  awk -v block="$rule" '
    BEGIN { inserted=0; in_filter=0 }
    /^\*filter$/ { in_filter=1 }
    in_filter && /^COMMIT$/ {
      if (!inserted) print block
      in_filter=0
    }
    { print }
    END {
      if (!inserted && !in_filter) {
        print ""
        print "*filter"
        print ":ufw-before-forward - [0:0]"
        print block
        print "COMMIT"
      }
    }
  ' "$conf" >"$tmp"
  mv -f -- "$tmp" "$conf"
}

update_ufw_forward() {
  local conf="/etc/default/ufw"
  local tmp=$(make_tmp_copy "$conf")

  sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' "$tmp"

  mv -f -- "$tmp" "$conf"
  ufw --force reload
}