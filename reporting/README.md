# retiremx reporting collector

The collector reads `/var/log/retiremx/events.jsonl` and stores
`recipient_decision` events in PostgreSQL. `event_id` is the primary key, so
restarts and rereading the log do not create duplicate rows.

On the target, create the environment file before starting:

```sh
cp /etc/retiremx-report/.env.example /etc/retiremx-report/.env
editor /etc/retiremx-report/.env
/etc/retiremx-report/start-reporting.sh
```

The PostgreSQL service is not published outside the Docker network.

The dashboard is published on the target host at `127.0.0.1:6873`. Configure
Apache to proxy the vhost to that address. It presents the most recent event
hours, then paginates the exact events within the selected hour, newest first.
Times are stored and returned as UTC; the browser renders them in local time.

The initial management UI is available at `/manage`. It shows the imported
recipient groups and allows adding, editing, searching, and deleting groups.
It also lists blocked sender rules and allows adding or removing them. The
main incoming-mail view has `Block sender` and `Block domain` actions on each
event row. The management page can export the current database configuration
as a portable `retiremx.md` file, or publish it directly to RetireMX.

The dashboard includes a recipient dropdown populated from the distinct
recipients stored in PostgreSQL. Selecting one filters the hour counts and
event pages. The `Senders for recipient` tab shows the distinct senders for
the selected recipient, grouped and paged by message count.

For messages that reach `DATA`, RetireMX captures the sanitized Subject and
Message-ID headers while streaming the message to Postfix. The message body is
never stored or logged. Envelope-only rejections have no subject metadata.

The JSON endpoints are:

- `/api/recipients` -> distinct recipients in the database
- `/api/hours?recipient=<address>` -> recent UTC hour buckets and counts
- `/api/events?hour_start=<unix-hour>&recipient=<address>&page=1&per_page=50` -> exact events
- `/api/senders?recipient=<address>&page=1&per_page=50` -> paged sender counts
- `/api/management/blocked-senders` -> manage blocked sender rules
- `/api/management/export` -> download the current configuration as Markdown
- `/api/management/publish` -> atomically publish the current configuration to RetireMX

Publishing writes to the shared path configured by `RETIREMX_CONFIG_PATH` in web
mode. The supplied Compose file mounts `/etc/retiremx` at `/retiremx-config` and
uses `/retiremx-config/retiremx.md`. RetireMX notices the atomic replacement,
validates the file, and reloads it automatically. Invalid configuration leaves
the currently active configuration unchanged.
The target start script repairs the host file to `root:retiremx` with group
write access; the web container uses UID 0 with the `retiremx` group so atomic
replacement preserves that ownership.

The same export is available from the command line:

```sh
retiremx-report \
  --mode export \
  --database-url "$DATABASE_URL" \
  --output /tmp/retiremx.md
```

The output file is written through a temporary file and renamed into place.

## Importing the initial management configuration

The reporting database has separate management tables for the desired
RetireMX configuration. The collector creates those tables at startup.

Import is a dry run unless `--apply --yes` are supplied:

```sh
sudo docker compose \
  --env-file /etc/retiremx-report/.env \
  -f /etc/retiremx-report/compose.yml \
  run --rm \
  -v /etc/retiremx/retiremx.md:/import/retiremx.md:ro \
  collector \
  --mode import \
  --input /import/retiremx.md
```

Apply the validated file and reinitialize the management configuration:

```sh
sudo docker compose \
  --env-file /etc/retiremx-report/.env \
  -f /etc/retiremx-report/compose.yml \
  run --rm \
  -v /etc/retiremx/retiremx.md:/import/retiremx.md:ro \
  collector \
  --mode import \
  --input /import/retiremx.md \
  --apply --yes
```

The import replaces the current management configuration in one transaction
and records the import summary. Publishing is a separate explicit action from
the management UI.
