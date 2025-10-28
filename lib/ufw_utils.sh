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
  local lan_cidr="$1"
  local lan_iface="$2"
  local wan_iface="$3"

  if [[ -z "$lan_cidr" || -z "$lan_iface" || -z "$wan_iface" ]]; then
    echo "usage: setup_forward <LAN_CIDR> <LAN_IFACE> <WAN_IFACE>"
    echo "e.g.:  setup_forward 10.10.0.0/24 wg0 eth0" >&2
    return 1
  fi

  echo -e "Enable core IP forwarding"
  enable_core_forward

  echo -e "Add NAT rule (masquerade $lan_cidr -> $wan_iface)"
  add_nat_forward_rules "$lan_cidr" "$wan_iface"

  echo "Add filter rule for forwarding ($lan_cidr -> $wan_iface)"
  add_filter_forward_rule "$lan_cidr" "$wan_iface"

  echo -e "Set UFW forward policy to ACCEPT"
  add_ufw_forward_policy

  echo -e "Allow routed traffic from LAN ($lan_iface) to WAN ($wan_iface)"
  ufw route allow in on "$lan_iface" out on "$wan_iface"

  ufw --force reload
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

add_nat_forward_rules() {
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

add_filter_forward_rule() {
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

add_ufw_forward_policy() {
  local conf="/etc/default/ufw"
  local tmp=$(make_tmp_copy "$conf")

  sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' "$tmp"

  mv -f -- "$tmp" "$conf"
}