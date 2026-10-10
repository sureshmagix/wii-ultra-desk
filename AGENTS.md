# WII Ultra Desk contributor rules

- Inspect the checkout, `git status`, project docs, and applicable nested
  `AGENTS.md` files before changing code. Preserve unrelated local changes;
  work on a feature branch and never reset, clean, force-push, commit, deploy,
  or publish unless explicitly asked.
- Use JavaScript/JSX for Electron, React, and Node coordination code. Do not
  add TypeScript to application code. Keep platform integration and background
  operation in the Rust agent.
- Keep Electron renderers sandboxed with context isolation and narrow,
  sender-validated IPC. Never disable Electron sandboxing, TLS verification,
  or SSH host-key checking to bypass a failure.
- Do not put passwords, signing keys, tokens, device private keys, or TURN
  shared secrets in source control or logs. Use protected OS storage for
  credentials and identity keys. Do not invent cryptographic protocols.
- Saved device bookmarks are locators only; they must stay separate from
  verified device identities and authorization grants. Unattended access is
  explicit opt-in, scoped, revocable, and enforced by the host.
- Treat remote control, SSH, file transfer, capture, input injection, and
  public coordinator endpoints as unavailable until the authenticated
  connectivity design and tests are implemented. Do not silently expand a
  foundation task into live remote access.
- Pin dependency versions and maintain lockfiles. Verify changes with the
  project scripts when the needed toolchains are available. State what was
  tested, untested, blocked, and planned without overstating platform or
  security coverage.
- Update `docs/PROGRESS.md` before handing off: changes, commands/results,
  blockers, and the exact next task.
