#!/usr/bin/env bash
# One-command LanMic install for Ubuntu / PipeWire.
#   curl -fsSL https://raw.githubusercontent.com/mahmoudhamdi26/lanmic/main/install.sh | bash
#   ./install.sh
#   ./install.sh --uninstall
set -euo pipefail

REPO_URL="${LANMIC_REPO:-https://github.com/mahmoudhamdi26/lanmic.git}"
DEFAULT_HOME="${LANMIC_HOME:-$HOME/.local/share/lanmic}"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT="$UNIT_DIR/lanmic.service"

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_apt() {
  local pkgs=("$@") missing=()
  for p in "${pkgs[@]}"; do
    dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
  done
  if ((${#missing[@]})); then
    need_cmd sudo || die "missing packages: ${missing[*]} (install them, then re-run)"
    log "Installing packages: ${missing[*]}"
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
  fi
}

resolve_root() {
  local here=""
  if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "bash" && "${BASH_SOURCE[0]}" != "-" ]]; then
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  fi
  if [[ -n "$here" && -f "$here/lanmic.py" ]]; then
    printf '%s' "$here"
    return
  fi
  if [[ -f "$DEFAULT_HOME/lanmic.py" ]]; then
    printf '%s' "$DEFAULT_HOME"
    return
  fi
  need_cmd git || install_apt git
  log "Cloning LanMic into $DEFAULT_HOME"
  mkdir -p "$(dirname "$DEFAULT_HOME")"
  if [[ -d "$DEFAULT_HOME/.git" ]]; then
    git -C "$DEFAULT_HOME" pull --ff-only
  else
    git clone --depth 1 "$REPO_URL" "$DEFAULT_HOME"
  fi
  printf '%s' "$DEFAULT_HOME"
}

write_unit() {
  local root="$1" python="$2"
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT" <<EOF
[Unit]
Description=LanMic phone microphone
After=pipewire.service pipewire-pulse.service
Wants=pipewire.service

[Service]
Type=simple
WorkingDirectory=$root
ExecStart=$python $root/lanmic.py --default --http-port 8767
Restart=on-failure
RestartSec=2
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
EOF
}

uninstall() {
  log "Stopping LanMic service"
  systemctl --user disable --now lanmic.service 2>/dev/null || true
  rm -f "$UNIT"
  systemctl --user daemon-reload 2>/dev/null || true
  log "Service removed. Project files were left in place."
}

install() {
  need_cmd python3 || die "python3 is required"
  install_apt python3-venv python3-pip pipewire-bin openssl qrencode
  need_cmd pw-cat || die "pw-cat not found (install pipewire-bin)"
  need_cmd openssl || die "openssl not found"

  local root python
  root="$(resolve_root)"
  log "Using $root"

  log "Creating virtualenv"
  python3 -m venv "$root/.venv"
  # shellcheck disable=SC1091
  python="$root/.venv/bin/python"
  "$python" -m pip install -U pip
  "$python" -m pip install -r "$root/requirements.txt"

  write_unit "$root" "$python"
  systemctl --user daemon-reload
  systemctl --user enable --now lanmic.service

  if command -v loginctl >/dev/null 2>&1; then
    if loginctl enable-linger "$USER" 2>/dev/null; then
      log "Linger enabled — LanMic can start at boot"
    else
      log "Could not enable linger (optional). Service still starts at login."
    fi
  fi

  sleep 0.4
  systemctl --user --no-pager --full status lanmic.service || true
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
  [[ -z "$ip" ]] && ip="YOUR_PC_IP"
  log "LanMic is installed and enabled on startup."
  log "Phone app: host $ip   port 8767"
  log "Browser:   https://$ip:8766"
  log "Status:    systemctl --user status lanmic"
}

case "${1:-}" in
  --uninstall|uninstall) uninstall ;;
  --help|-h) sed -n '2,6p' "$0" ;;
  *) install ;;
esac
