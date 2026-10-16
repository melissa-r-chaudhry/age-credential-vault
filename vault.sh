#!/bin/bash
# age-credential-vault — age-encrypted, passphrase-gated-at-unlock-only secret store.
#
# Design: a single age identity keypair gates the whole vault. The private
# key (identity.age) is itself passphrase-encrypted — that's the one and only
# passphrase, needed only at `unlock`. The vault (vault.age) is encrypted to
# the matching public key (recipient.txt, plaintext, not a secret), which
# means writing to it never needs a passphrase or a terminal — only the
# decrypted identity key in RAM does. So: unlock once (interactive,
# passphrase), then get/set/rm/list all work non-interactively until lock.
set -euo pipefail

VAULT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_FILE="$VAULT_DIR/vault.age"
IDENTITY_FILE="$VAULT_DIR/identity.age"
RECIPIENT_FILE="$VAULT_DIR/recipient.txt"
RAM_LABEL="SecretVaultRAM"
PID_FILE="$VAULT_DIR/.timer.pid"
EXPIRY_FILE="$VAULT_DIR/.expiry"
DEV_FILE="$VAULT_DIR/.devpath"
MOUNT_FILE="$VAULT_DIR/.mountpoint"
DURATION_FILE="$VAULT_DIR/.duration"
LOCK_DIR="$VAULT_DIR/.writelock"
AGE_BIN="${AGE_BIN:-/usr/local/bin/age}"
AGE_KEYGEN_BIN="${AGE_KEYGEN_BIN:-/usr/local/bin/age-keygen}"
DEFAULT_MINUTES=2

reap_stale() {
  if [ -f "$DEV_FILE" ]; then
    stale_dev="$(cat "$DEV_FILE" 2>/dev/null || true)"
    if [ -n "${stale_dev:-}" ]; then
      hdiutil detach "$stale_dev" -force >/dev/null 2>&1 || true
    fi
    rm -f "$DEV_FILE" "$MOUNT_FILE"
  fi
}

is_unlocked() {
  # -s (not just -f): a failed decrypt (wrong passphrase, or no tty to prompt
  # on) can leave a 0-byte identity file behind via shell redirection even
  # though age itself never succeeded — that must not read as "unlocked".
  [ -f "$MOUNT_FILE" ] && [ -f "$DEV_FILE" ] && mount | grep -qF " $(cat "$MOUNT_FILE") " && [ -s "$(identity_path)" ]
}

identity_path() {
  echo "$(cat "$MOUNT_FILE")/identity.txt"
}

# mkdir is atomic on a local filesystem, so it doubles as a mutex (macOS has
# no `flock` binary by default). Guards the read-modify-write in set/rm so two
# concurrent writers can't silently clobber each other's change.
acquire_write_lock() {
  local waited=0
  while ! mkdir "$LOCK_DIR" 2>/dev/null; do
    # break a lock left behind by a crashed process rather than hang forever
    if [ -d "$LOCK_DIR" ]; then
      lock_age=$(( $(date +%s) - $(stat -f %m "$LOCK_DIR" 2>/dev/null || echo 0) ))
      if [ "$lock_age" -gt 30 ]; then
        rm -rf "$LOCK_DIR"
        continue
      fi
    fi
    sleep 0.2
    waited=$((waited + 1))
    if [ "$waited" -gt 100 ]; then
      echo "Vault is busy (another write in progress) — try again." >&2
      exit 1
    fi
  done
}

release_write_lock() {
  rmdir "$LOCK_DIR" 2>/dev/null || true
}

cancel_timer() {
  if [ -f "$PID_FILE" ]; then
    old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "${old_pid:-}" ] && kill -0 "$old_pid" 2>/dev/null; then
      kill "$old_pid" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
  fi
}

do_lock() {
  cancel_timer
  if [ -f "$DEV_FILE" ]; then
    dev="$(cat "$DEV_FILE" 2>/dev/null || true)"
    if [ -n "${dev:-}" ]; then
      hdiutil detach "$dev" -force >/dev/null 2>&1 || true
    fi
  fi
  rm -f "$DEV_FILE" "$MOUNT_FILE" "$EXPIRY_FILE" "$DURATION_FILE"
  echo "Vault locked. Identity key destroyed."
}

start_timer() {
  minutes="$1"
  cancel_timer
  echo "$minutes" > "$DURATION_FILE"
  date -v+"${minutes}"M +%s > "$EXPIRY_FILE" 2>/dev/null || date -d "+${minutes} minutes" +%s > "$EXPIRY_FILE"
  # Redirect the WHOLE subshell's I/O, not just the inner command's — over
  # SSH, a background grandchild that still holds a copy of the session's
  # stdin/stdout/stderr will keep the remote side from closing the
  # connection back to the caller until it exits, even if it's just sleeping.
  ( sleep "$((minutes * 60))"; "$VAULT_DIR/vault.sh" lock >/dev/null 2>&1 ) </dev/null >/dev/null 2>&1 &
  disown
  echo $! > "$PID_FILE"
}

# Every real touch of the vault (get/set/rm/list) calls this so the lock
# reflects N minutes of *inactivity*, not a flat timer from the moment of
# unlock — a burst of activity near the deadline should not lock mid-use.
touch_activity() {
  mins="$(cat "$DURATION_FILE" 2>/dev/null || echo "$DEFAULT_MINUTES")"
  start_timer "$mins"
}

# Creates a fresh RAM disk and records its device path + real mount point
# (never assumed — macOS silently renames on a name collision, e.g. "...1")
# so every other command can find it reliably.
make_ramdisk() {
  reap_stale
  dev="$(hdiutil attach -nomount ram://16384 | tr -d '[:space:]')"
  diskutil eraseVolume HFS+ "$RAM_LABEL" "$dev" >/dev/null
  mp="$(diskutil info "$dev" | awk -F': *' '/Mount Point/ {print $2}')"
  if [ -z "$mp" ]; then
    hdiutil detach "$dev" -force >/dev/null 2>&1 || true
    echo "Failed to determine RAM disk mount point." >&2
    exit 1
  fi
  echo "$dev" > "$DEV_FILE"
  echo "$mp" > "$MOUNT_FILE"
}

do_unlock() {
  minutes="${1:-$DEFAULT_MINUTES}"
  if is_unlocked; then
    start_timer "$minutes"
    echo "Already unlocked. Auto-lock timer reset to ${minutes} minutes."
    return
  fi
  if [ ! -f "$IDENTITY_FILE" ] || [ ! -f "$VAULT_FILE" ]; then
    echo "No vault found. Run: vault.sh init" >&2
    exit 1
  fi
  make_ramdisk
  echo "Enter vault passphrase:"
  if ! "$AGE_BIN" -d "$IDENTITY_FILE" > "$(identity_path)" || [ ! -s "$(identity_path)" ]; then
    do_lock >/dev/null
    echo "Unlock failed (wrong passphrase, or no terminal available to prompt for one) — vault left locked, nothing left behind." >&2
    exit 1
  fi
  chmod 600 "$(identity_path)"
  start_timer "$minutes"
  echo "Vault unlocked for ${minutes} minutes. get/set/rm/list work without re-entering the passphrase until lock."
}

do_init() {
  if [ -f "$IDENTITY_FILE" ] || [ -f "$VAULT_FILE" ]; then
    echo "Vault already exists — refusing to overwrite." >&2
    exit 1
  fi
  make_ramdisk
  ram="$(cat "$MOUNT_FILE")"
  "$AGE_KEYGEN_BIN" -o "$ram/identity.txt" 2>/dev/null
  pubkey="$("$AGE_KEYGEN_BIN" -y "$ram/identity.txt")"
  echo "$pubkey" > "$RECIPIENT_FILE"
  echo "Set the vault's master passphrase (you will type it twice) — this is the only passphrase, ever:"
  "$AGE_BIN" -p -o "$IDENTITY_FILE" "$ram/identity.txt"
  echo '{}' | "$AGE_BIN" -r "$pubkey" -o "$VAULT_FILE"
  do_lock
  echo "Vault created. Public recipient key stored at $RECIPIENT_FILE (not a secret)."
}

do_get() {
  key="$1"
  if ! is_unlocked; then
    echo "Vault is locked. Run: vault.sh unlock" >&2
    exit 1
  fi
  val="$("$AGE_BIN" -d -i "$(identity_path)" "$VAULT_FILE" | jq -er --arg k "$key" '.[$k] // empty')" \
    || { echo "No such key: $key" >&2; exit 1; }
  touch_activity
  echo "$val"
}

do_list() {
  if ! is_unlocked; then
    echo "Vault is locked. Run: vault.sh unlock" >&2
    exit 1
  fi
  "$AGE_BIN" -d -i "$(identity_path)" "$VAULT_FILE" | jq -r 'keys[]'
  touch_activity
}

do_set() {
  key="$1"; val="$2"
  if ! is_unlocked; then
    echo "Vault is locked. Run: vault.sh unlock" >&2
    exit 1
  fi
  acquire_write_lock
  trap release_write_lock EXIT
  recipient="$(cat "$RECIPIENT_FILE")"
  tmp_json="$(cat "$MOUNT_FILE")/vault.json.tmp"
  tmp_age="$VAULT_DIR/.vault.age.tmp"
  "$AGE_BIN" -d -i "$(identity_path)" "$VAULT_FILE" | jq --arg k "$key" --arg v "$val" '.[$k] = $v' > "$tmp_json"
  "$AGE_BIN" -r "$recipient" -o "$tmp_age" "$tmp_json"
  mv "$tmp_age" "$VAULT_FILE"
  rm -f "$tmp_json"
  touch_activity
  echo "Set '$key'."
}

do_rm() {
  key="$1"
  if ! is_unlocked; then
    echo "Vault is locked. Run: vault.sh unlock" >&2
    exit 1
  fi
  acquire_write_lock
  trap release_write_lock EXIT
  recipient="$(cat "$RECIPIENT_FILE")"
  tmp_json="$(cat "$MOUNT_FILE")/vault.json.tmp"
  tmp_age="$VAULT_DIR/.vault.age.tmp"
  "$AGE_BIN" -d -i "$(identity_path)" "$VAULT_FILE" | jq --arg k "$key" 'del(.[$k])' > "$tmp_json"
  "$AGE_BIN" -r "$recipient" -o "$tmp_age" "$tmp_json"
  mv "$tmp_age" "$VAULT_FILE"
  rm -f "$tmp_json"
  touch_activity
  echo "Removed '$key'."
}

do_status() {
  if is_unlocked; then
    if [ -f "$EXPIRY_FILE" ]; then
      now="$(date +%s)"
      exp="$(cat "$EXPIRY_FILE")"
      remaining=$(( (exp - now) / 60 ))
      echo "Unlocked. Auto-locks after ~${remaining} more minute(s) of inactivity."
    else
      echo "Unlocked (no expiry tracked)."
    fi
  else
    echo "Locked."
  fi
}

cmd="${1:-}"
shift || true
case "$cmd" in
  init) do_init ;;
  unlock) do_unlock "${1:-$DEFAULT_MINUTES}" ;;
  lock) do_lock ;;
  status) do_status ;;
  get) do_get "$1" ;;
  list) do_list ;;
  set) do_set "$1" "$2" ;;
  rm) do_rm "$1" ;;
  *)
    cat >&2 <<EOF
Usage: vault.sh <command> [args]
  init                  create a new vault (one-time; sets the master passphrase)
  unlock [minutes]      decrypt identity key to RAM, auto-lock after [minutes] (default $DEFAULT_MINUTES)
  lock                  immediately destroy the RAM-held identity key
  status                show locked/unlocked + time remaining
  get <key>             print a secret's value (must be unlocked)
  list                  list all keys (must be unlocked)
  set <key> <value>     add/update a secret — no passphrase needed once unlocked
  rm <key>              delete a secret — no passphrase needed once unlocked
EOF
    exit 1
    ;;
esac
