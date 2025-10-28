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