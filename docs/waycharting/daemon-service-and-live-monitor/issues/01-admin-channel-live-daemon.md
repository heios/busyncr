# 01 — Admin channel: how a live daemon answers status and control

- Type: grilling
- Status: open
- Blocked by: none

## Question

The redb store is exclusive-lock, so `busyncr-daemon status` cannot run as a
separate process while `serve` is up — yet live monitoring is a hard
requirement. The `serve` process itself must answer. Decide the admin
channel:

1. **Transport** — options to grill through:
   - admin RPCs on the *existing* mTLS gRPC listener (operator needs a
     client-style cert; remote-capable by construction);
   - a second loopback-only listener (plain gRPC or HTTP/JSON on
     127.0.0.1, no TLS, reachable only from the daemon host);
   - a Unix domain socket / Windows named pipe with filesystem/ACL
     permissions as the auth boundary.
2. **AuthN/AuthZ** — who may ask, and is there an operator identity
   distinct from enrolled backup clients? (Revocation and quota-setting are
   more dangerous than reading stats.)
3. **Operation set riding the channel** — read: the full monitor payload
   (ticket 03). Control: set-quota (ticket 04), trigger prune/gc, mint
   enrollment token, revoke a client? Which of the existing offline
   subcommands grow a `--live` path vs stay store-offline-only?
4. **CLI ergonomics** — does `busyncr-daemon status` transparently try the
   live channel first and fall back to opening the store, or is live an
   explicit mode?

The answer fixes the "basic interface" of the whole monitor; tickets 04 and
06 are blocked on it. /design-an-interface is a good vehicle before the
grilling settles it.
