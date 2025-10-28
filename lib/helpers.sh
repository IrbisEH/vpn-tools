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