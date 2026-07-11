# 02 — Service mechanics for busyncr-daemon on Windows, macOS, Linux

- Type: research
- Status: open
- Blocked by: none

## Question

How does busyncr-daemon install and run as a supervised background service
on each platform, and what CLI surface wraps it? Produce a markdown note
(linked asset) covering:

- **Windows**: the client already integrates with the SCM via the
  `windows-service` crate (`crates/busyncr-client/src/service.rs`,
  PRD §3.6) — how much of that pattern transfers to the daemon
  (`busyncr-daemon service install|start|stop|uninstall`)? Event-log
  logging, service account (LocalService vs LocalSystem — the store needs
  write access), startup type, recovery/restart-on-crash settings.
- **macOS**: LaunchDaemon (not LaunchAgent — must run without a login
  session). Plist location and contents (`KeepAlive`, `RunAtLoad`,
  stdout/stderr paths), root vs a dedicated `_busyncr` user, whether the
  binary self-installs the plist (`service install` writing to
  `/Library/LaunchDaemons` + `launchctl bootstrap`) or ships a documented
  template. TCC/full-disk-access implications for the store path.
- **Linux**: a documented systemd unit (Type=simple, the existing SIGTERM
  graceful shutdown already fits) — shipped file vs README snippet.
- **Cross-cutting**: config source when there are no CLI args (the service
  can't take `--store` from an operator's shell — daemon config file
  location per platform), log destination when detached from a terminal
  (tracing already in the palette), and how `service status` relates to the
  admin channel (ticket 01).

Constraint: AGENTS.md palette — `windows-service` is already approved;
anything new (e.g. a launchd/plist crate) needs a Cargo.toml justification
or hand-rolled XML.
