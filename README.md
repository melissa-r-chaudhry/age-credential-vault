# age-credential-vault

A password-gated, RAM-only-decrypted secret store for small, self-hosted
infrastructure — built to replace credentials sitting in plaintext
config/notes files with something that's encrypted at rest, requires a
passphrase exactly once per session, and never leaves a usable plaintext
copy on disk.

Single dependency: [age](https://github.com/FiloSottile/age), plus `jq`
and standard macOS/BSD tools. No server, no daemon, no database.

## Why not just `.env` files or a password manager API

- `.env`/plaintext-notes credential storage means anyone who can read the
  filesystem (or a backup of it) has every secret, unencrypted, forever.
- A hosted secrets-manager API is a reasonable choice for a team with a
  budget and a server fleet to match — this is for the smaller case: a
  single operator who wants real encryption at rest without standing up
  infrastructure for infrastructure's sake.

## Design

**Two-key split, not simple passphrase-symmetric encryption** — this is
the piece that makes "unlock once, write freely" possible:

- `identity.age` — an `age-keygen` private key, itself encrypted with the
  master passphrase. This is the *only* passphrase-gated file, and only
  `unlock` ever touches it.
- `recipient.txt` — the matching **public** key, stored in plaintext (not
  a secret — it's just where secrets get encrypted *to*).
- `vault.age` — the actual secrets (a JSON blob), encrypted to
  `recipient.txt`'s public key. Encrypting to a recipient key needs no
  passphrase and no terminal, so `set`/`rm` can run completely
  non-interactively once unlocked.

**Unlock mechanics:**
1. `unlock [minutes]` creates an ephemeral RAM disk, decrypts
   `identity.age` into it (the one and only passphrase prompt), and starts
   an inactivity timer.
2. `get`/`list` decrypt `vault.age` on the fly using the RAM-resident
   identity key — no passphrase.
3. `set`/`rm` do the same, re-encrypt to the recipient key, and atomically
   replace the vault file — no passphrase.
4. `lock` (manual, or auto-fired by the inactivity timer) detaches the RAM
   disk, destroying the only plaintext copy of the identity key that ever
   existed. Every command after that requires `unlock` again.
5. Auto-lock resets on every real `get`/`set`/`rm`/`list` — it's an
   *inactivity* timer, not a flat countdown from unlock, so a burst of
   activity near the deadline doesn't lock mid-use.

Pair this with a periodic off-host copy of just the three already-encrypted
files (`identity.age`, `recipient.txt`, `vault.age`) — never the RAM disk,
never anything decrypted — verified by checksum rather than trusting a
copy's exit code. Even if the backup destination itself were compromised,
the backup is still behind the same passphrase gate the live vault is.

## Real bugs found and fixed building this

Worth reading if you're adapting this pattern — these were genuine, not
hypothetical:

- **`diskutil unmount force` does not release a `hdiutil attach ram://`
  device.** It only unmounts the filesystem; the RAM disk device stays
  attached (and keeps consuming RAM) until `hdiutil detach <dev> -force`.
- **macOS silently renames a volume on a name collision** (`Foo` → `Foo 1`
  → `Foo 2` if a prior RAM disk with the same label wasn't fully torn
  down). A script that assumes a fixed mount path will silently operate on
  nothing. Fixed by reading the real mount point back from `diskutil info`
  every time, never assuming it.
- **Interrupted runs can orphan a RAM disk holding plaintext** — a
  Ctrl+C mid-passphrase-entry leaves a device attached with nothing
  cleaning it up. Fixed with a `reap_stale()` pass at the start of every
  `unlock`/`init`.
- **A failed decrypt can leave a 0-byte identity file behind**, because
  shell output redirection (`> file`) creates the destination immediately
  regardless of whether the command itself succeeds. A naive
  `[ -f identity.txt ]` check would then report "unlocked" after a failed
  attempt, with a RAM disk mounted and nothing usable inside it. Fixed by
  checking `-s` (non-empty), not just `-f`.
- **A background auto-lock timer, run over SSH, held the calling session
  open for the full timer duration** — redirecting only the inner `lock`
  command's I/O isn't enough; the `sleep` itself, as the subshell's first
  process, still inherits the caller's stdin/stdout/stderr. A remote shell
  won't close the connection back until every process holding a duplicate
  of those file descriptors exits, even a backgrounded, `disown`'d one
  that's just sleeping. Fixed by redirecting the *entire* subshell's I/O,
  not just the command inside it.
- **A read-modify-write race in `set`/`rm`:** two concurrent writers could
  silently clobber each other's change, since nothing serialized
  decrypt → edit → re-encrypt → replace. Fixed with an `mkdir`-based mutex
  (macOS ships no `flock` binary) wrapping both write paths, released via
  an `EXIT` trap so a mid-write failure can't leave it stuck locked.
  Verified with two concurrent writers touching different keys — both
  persisted, no data loss.

## The audit that matters most (`audit_unwrap.py`)

A credential-migration script can introduce a subtle, silent bug: storing
a whole metadata record (`{"value": "...", "created": ..., ...}`) under a
key instead of extracting just the real secret value. `vault.sh get`
round-trips this perfectly either way — nothing *looks* wrong until
something tries to actually authenticate with the stored value and fails.

`audit_unwrap.py` checks every key for exactly this pattern and, with
`--fix`, extracts the real value and re-sets it — verifying a clean
round-trip on every single key before moving to the next one, rather than
trusting the write succeeded.

Running this against a real vault populated by a batch-migration script
found that **the large majority of entries had been silently wrapped this
way since the original migration** — a systemic bug from one script
affecting one batch, not scattered one-off mistakes. Every affected entry
was confirmed fixed with a verified round-trip before being considered
done, with a full pre-fix backup taken first.

## Commands

```
vault.sh init                 # one-time, sets the master passphrase
vault.sh unlock [minutes]     # default 2; interactive, passphrase required
vault.sh lock                 # manual immediate lock
vault.sh status                # locked/unlocked + inactivity time remaining
vault.sh get <key>
vault.sh list
vault.sh set <key> <value>
vault.sh rm <key>
```

## Access model — read before relying on this

Unlock state is a *machine-level* fact (a RAM disk + a few marker files),
not scoped to whichever process or session called `unlock`. Any process
with filesystem access to the vault directory can read/write while it's
unlocked. There is no technical partition by "who unlocked it." This is a
deliberate tradeoff for a single-operator tool, not an oversight — know it
before adopting this pattern for a multi-user setting.
