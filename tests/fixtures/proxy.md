# Defaults

Reject Sender Without MX: false

Reject Null Sender: false

Reject Managed Sender Spoofing: false

# Postfix

Host: 127.0.0.1

Port: 2533

# Trusted Senders

## trusted.example

Action: pass-through

Verify: none

# Addresses

## old@example.test

Replaced By:

- new@example.net
