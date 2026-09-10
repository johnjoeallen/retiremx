# retiremx

SMTP address migration and routing front end.

## Current implementation

```text
Markdown config
    -> parser
    -> validation
    -> retired-address resolver
    -> query mode
    -> SMTP listener
    -> sender policy and MX verification
    -> structured logs
    -> Postfix SMTP proxy
```

- groups
- nested groups
- one-member groups
- every known address returns `550`
- replacement addresses
- `and` replacement formatting
- lowercase address normalization
- dot- and plus-normalized local-part matching
- wildcard domains such as `classesarecode.*`
- anonymous domains such as `john.allen@`
- duplicate destination removal
- cycle detection
- plain-text query output
- JSON query output
- SMTP `550` migration responses
- unknown-address reject or pass-through policy
- sender and domain pass-through rules
- MX verification with failed-verification discovery logs
- per-address pass-through mode
- Postfix proxying over loopback TCP
- SIGHUP configuration reload

Unknown addresses are configurable:

```text
unknown
    -> reject
    -> or pass-through

Known addresses have their own default action. For an initial deployment that
observes all traffic while handing it to Postfix:

```markdown
# Defaults

Known Action: pass-through
Unknown Action: pass-through
```

Sender domains without MX records are rejected by default at `MAIL FROM`:

```markdown
# Defaults

Reject Sender Without MX: true
```

To allow DNS-less sender domains during a migration or test deployment:

```markdown
Reject Sender Without MX: false
```

Null senders are also configurable:

```markdown
Reject Null Sender: true

Reject Managed Sender Spoofing: true
```

Set it to `false` to continue processing null senders. An MX/IP mismatch for
an allowed `Verify: mx` pass-through sender is logged as a warning but does not
prevent pass-through.

Managed sender spoofing is independently checked. A sender using one of the
managed domains is accepted only from loopback or when the connecting IP
matches that domain's MX records. Disable this check only when the managed
domain legitimately sends through other infrastructure:

```markdown
Reject Managed Sender Spoofing: false
```

Individual known addresses can override the default:

```markdown
Pass Through: false
```
```

## Query

```sh
cargo run -- --config examples/retiremx.md query oldjohn@moyville.net
cargo run -- --config examples/retiremx.md query --output json house@moyville.net
echo oldparents@moyville.net | cargo run -- --config examples/retiremx.md query
```

Plain query results, including unknown-address messages, are written to stdout. Structured operational logs are written to stderr.

Resolution flow:

```text
oldjohn@moyville.net
    -> john@example.net

house@moyville.net
    -> parents@moyville.net
    -> mum@example.net
    -> dad@example.net
    -> child@example.net
```

## Service

The production service is named `retiremx`:

```sh
retiremx --config /etc/retiremx/retiremx.md smtp
```

The systemd unit is `retiremx.service`. Configuration files are hand-crafted Markdown; there is no database importer.

After editing `/etc/retiremx/retiremx.md`, reload it without stopping SMTP:

```sh
sudo systemctl reload retiremx
```

The new configuration is parsed and validated before it replaces the active
configuration. Invalid changes are rejected and the previous configuration
continues running.

When the reporting management UI is deployed, its `Publish to RetireMX` action
writes the exported management configuration atomically to this same file.
RetireMX detects that replacement, validates it, and reloads it automatically.

RetireMX only accepts recipients in managed domains. Configure them explicitly:

```markdown
# Server

Managed Domains:

- moyville.net
```

Recipients outside these domains receive `550 5.7.1 Relay access denied` at
`RCPT TO` and are never sent to Postfix. If `Managed Domains` is omitted, the
domains of configured addresses are used as the managed-domain set.

Sender blocking happens at `MAIL FROM` and returns `550 5.7.1` before recipient processing:

```markdown
# Blocked Senders

## jobs@moyville.net

## @mail.gl1pro.shop

## *@spam.example

## /^(?:notice|alerts)@bad.example$/
```

Patterns support exact addresses, exact sender domains using an `@` prefix,
glob wildcards (`*` and `?`), and slash-delimited regular expressions. Matching
is case-insensitive. Regular expressions use Rust's bounded regular-expression
engine rather than backtracking evaluation.

Idle SMTP connections are limited by `Idle Timeout Seconds` (60 seconds by
default). A client that connects but sends no command is closed and logged as
`connection_idle_timeout`. Its IP address is then quarantined in memory for
one hour; subsequent connections receive `421 4.7.0` immediately and are
logged as `connection_rejected_quarantined`. The quarantine is bounded to
10,000 IP addresses and expires automatically.

When `Reject Sender Without MX` is enabled, a sender domain with no MX record
is rejected at `MAIL FROM`. A confirmed no-MX result is cached for one hour,
so repeated attempts from the same domain do not trigger a DNS lookup each
time.

The Debian systemd service writes reportable structured events to `/var/log/retiremx/events.jsonl` and also writes them to stderr/journald. Every event has a unique `event_id` UUID, allowing a reporting service to ingest the file idempotently. Enable the same log for manual runs with `--event-log PATH`.

Successful proxied messages produce a `postfix_accepted` event after Postfix
returns its final `2xx` response. It includes the sender, recipients, backend
address, and Postfix response. Backend connection, temporary failure, and
rejection events remain separate, so a `postfix_connected` event is not
mistaken for message acceptance.

Deployment helpers:

```sh
./scripts/build-deb-and-deploy.sh
```

This builds the Debian package and uploads it to `mail.moyville.net:/tmp`. When the reporting implementation exists in `reporting/`, it also uploads that stack to `/etc/retiremx-report/`. The target-side startup helper is `start-reporting.sh`.

Single replacements are one-member groups:

```text
john@moyville.net
    -> [john@example.net]

parents@moyville.net
    -> [mum@example.net, dad@example.net]
```

Domain matching:

```text
john.allen@moyville.net
    -> exact or normalized match

john.allen@classesarecode.*
    -> any classesarecode TLD

john.allen@
    -> any domain

john.allen+rc.mag@moyville.net
    -> replacement+rc.mag@example.net
```

Multiple source addresses may share one replacement list:

```markdown
## john.allen@moyville.net

## johnallen@moyville.net

Replaced By:

- john@example.net
```

An address may override the default rejection text:

```markdown
## old-contact@moyville.net

Replaced By:

- contact@example.net

Message: This address moved to the contact team.
```

## Development

```sh
cargo test
```

Try the example configuration with stdin:

```sh
echo oldjohn@moyville.net | ./scripts/query-example.sh
cat addresses.txt | ./scripts/query-example.sh
```

The binary also reads stdin when no subcommand is supplied:

```sh
cargo run -- --config examples/retiremx.md
```

Then type one address per line and press Enter. Each result is printed immediately; `Ctrl-D` exits.

Or pass addresses directly:

```sh
./scripts/query-example.sh john.allen@moyville.net
```

The explicit `smtp` command starts the SMTP listener.

Server settings can be kept in the Markdown file:

```markdown
# Server

Hostname: mx.example.net

Bind: 0.0.0.0

Port: 25
```

An explicit `smtp --bind` value overrides the Markdown bind setting.

Run the current SMTP listener locally:

```sh
cargo run -- --config examples/retiremx.md smtp --bind 127.0.0.1:2525
```

The port can also be overridden independently:

```sh
cargo run -- --config examples/retiremx.md smtp --port 2525
```

Address and port may be supplied separately:

```sh
cargo run -- --config examples/retiremx.md smtp --bind 127.0.0.1 --port 2525
```

The systemd service does not override `Bind`; its listener address and port come from `/etc/retiremx/retiremx.md`.

On `SIGTERM` or `SIGINT`, retiremx stops accepting new connections and allows active sessions up to 30 seconds to finish.

## Debian package

The repository includes a native Debian package layout under `debian/`:

```sh
dpkg-buildpackage -us -uc -b
```

The package installs the binary, systemd unit, and `/etc/retiremx/retiremx.md`, and creates the `retiremx` system user and group during installation.

Current SMTP behavior:

- retired addresses return `550 5.1.1`
- unknown addresses follow `Unknown Action`
- `EHLO`, `HELO`, `MAIL FROM`, `RCPT TO`, `RSET`, `NOOP`, `DATA`, and `QUIT` are recognized
- `EHLO` advertises `SIZE` using `Max Data Bytes`
- standard ESMTP envelope parameters such as `SIZE` are accepted
- declared message sizes above the configured limit are rejected at `MAIL FROM`
- pass-through recipients are proxied to the configured Postfix SMTP listener
- SMTP lines are limited to 1000 bytes
- maximum 100 active connections
- maximum 100 pass-through recipients per transaction
- maximum proxied message size is 10 MiB

These limits can be overridden under `# Defaults`:

```markdown
Max Connections: 100
Max Line Bytes: 1000
Max Recipients: 100
Max Data Bytes: 10485760
```

Trusted senders can bypass migration handling:

```markdown
# Trusted Senders

## trusted.example

Action: pass-through

Verify: none
```

Sender-domain rules match the domain after `@`; exact sender rules use the complete address.

## systemd

Install [deploy/retiremx.service](/home/jallen/git/retiremx/deploy/retiremx.service), create the `retiremx` service user and group, and place the hand-crafted configuration at:

```text
/etc/retiremx/retiremx.md
```

For a local installation from a release build:

```sh
./scripts/build-release.sh
sudo groupadd --system retiremx
sudo useradd --system --gid retiremx --home-dir /nonexistent --shell /usr/sbin/nologin retiremx
sudo install -d -o retiremx -g retiremx -m 0750 /etc/retiremx
sudo install -m 0644 examples/retiremx.md /etc/retiremx/retiremx.md
sudo install -m 0755 target/release/retiremx /usr/local/bin/retiremx
sudo install -m 0644 deploy/retiremx.service /etc/systemd/system/retiremx.service
```

Then enable it:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now retiremx.service
journalctl -u retiremx.service -f
```

After editing the configuration, reload it without dropping the listener:

```sh
sudo systemctl kill -s HUP retiremx.service
```

The new file is parsed and validated before it replaces the active configuration. Invalid changes are logged and leave the previous configuration in use.

An address can be configured to log its would-be `550` response and pass the original recipient through to Postfix:

```markdown
## monitored@moyville.net

Replaced By:

- john@example.net

Pass Through: true
```
