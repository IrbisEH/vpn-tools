install_wireguard() {
  DEBIAN_FRONTEND=noninteractive apt install -y wireguard
}

configure_wireguard() {
  local iface="$1"
  local ip="$2"
  local prefix="$3"
  local port="$4"
  local private_key="$5"

  if [[ -z "$iface" || -z "$ip" || -z "$prefix" || -z "$port" || -z "$private_key" ]]; then
    echo -e "usage: configure_wireguard <WG_IFACE> <WG_SERVER_IP> <WG_SERVER_PREFIX> <WG_PRIVATE_KEY>"
    echo -e "e.g.:  configure_wireguard wg0 10.0.0.1 32 SOME_KEY"
  fi

  local rules
  local conf="/etc/wireguard/${iface}"
  local tmp=$(make_tmp)

  cat <<EOF > "$tmp"
[Interface]
Address = ${ip}/${prefix}
ListenPort = ${port}
PrivateKey = ${private_key}
SaveConfig = true
EOF

  mv -f -- "$tmp" "$conf"
}