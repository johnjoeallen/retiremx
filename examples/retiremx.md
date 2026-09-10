# Defaults

Unknown Message: No such address

Unknown Action: pass-through

Known Action: pass-through

Reject Sender Without MX: true

Reject Null Sender: true

Reject Managed Sender Spoofing: true

Retired Message: This address is no longer in use

Max Connections: 100

Idle Timeout Seconds: 60

Max Line Bytes: 1000

Max Recipients: 100

Max Data Bytes: 10485760

# Server

Hostname: mx.moyville.net

Managed Domains:

- localhost
- localhost.moyville.net
- moyville.net
- dublinux.com
- dublinux.net
- 7huntersleap.net
- classesarecode.com
- classesarecode.net
- classesarecode.org
- dailykebab.net
- rubyband.com

Bind: 0.0.0.0:25

# Postfix

Host: 127.0.0.1

Port: 2525

# Trusted Senders

## trusted.example

Action: pass-through

Verify: none

# Blocked Senders

## jobs@moyville.net

## @mail.gl1pro.shop

## *@spam.example

## /^(?:notice|alerts)@bad.example$/

# Addresses

## oldjohn@moyville.net

Replaced By:

- john@example.net

## monitored@moyville.net

Replaced By:

- john@example.net

Pass Through: true

## oldparents@moyville.net

Replaced By:

- mum@example.net
- dad@example.net

## parents@moyville.net

Replaced By:

- mum@example.net
- dad@example.net

## house@moyville.net

Replaced By:

- parents@moyville.net
- child@example.net

## john.allen@moyville.net

## johnallen@moyville.net

Replaced By:

- john@example.net

## john.allen@classesarecode.*

Replaced By:

- john@example.net

## john.allen@

Replaced By:

- john.joe.allen@gmail.com

## parents@

Replaced By:

- john.joe.allen@gmail.com
- lydiaredford@hotmail.com
