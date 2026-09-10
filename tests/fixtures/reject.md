# Defaults

Unknown Action: reject

Known Action: reject

Reject Sender Without MX: false

Reject Null Sender: false

Reject Managed Sender Spoofing: false

# Server

Hostname: localhost

Managed Domains:

- moyville.net

# Postfix

Host: 127.0.0.1

Port: 2525

# Trusted Senders

## trusted.example

Action: pass-through

Verify: none

# Addresses

## oldjohn@moyville.net

Replaced By:

- john@example.net

## monitored@moyville.net

Replaced By:

- john@example.net

Pass Through: true
