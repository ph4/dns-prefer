# dns-prefer

A DNS proxy that enforces IP version preference per domain. When a domain matches a rule, it checks whether the preferred record type exists — if so, queries for the other type are blocked.

## Usage

```shell
dns-prefer [options]

Options:
  -s string   upstream DNS server (default "1.1.1.1:53")
  -l string   listen address (default "0.0.0.0:5367")
  -c string   rule config file path (default "/etc/dns-prefer.conf")
  -e int      cache expire time in seconds (default 3600)
  -m int      cache size (default 6000)
```

## Rule config

Each rule ends with `@4` (prefer IPv4, block AAAA if A exists) or `@6` (prefer IPv6, block A if AAAA exists).

### Rule types

| Format | Type | Description |
|--------|------|-------------|
| `example.com@4` | suffix | Matches `example.com` and all subdomains |
| `strict:example.com@4` | strict | Exact domain match only |
| `regex:.*\.example\.com@4` | regex | Match by regular expression |
| `cidr:192.168.1.0/24@6` | cidr | Block query if resolved IP falls in CIDR range |

### Example config

```
# Prefer IPv4 for Google domains
google.com@4

# Prefer IPv6 for this exact domain only
strict:www.youtube.com@6

# Prefer IPv4 for domains matching regex
regex:.*\.bilibili\.com@4

# If resolved A record is in this range, block it when AAAA exists
cidr:192.168.0.0/16@6
```

Comments start with `#` and blank lines are ignored.

### CIDR rule behavior

CIDR rules only take effect when no domain rule matches the queried domain. They are evaluated after the upstream response is received. If a resolved IP falls within the CIDR range and the preferred record type (`@4` → A, `@6` → AAAA) also exists, the response is blocked. The result is cached for subsequent requests.

## Example

```shell
# Start the proxy
dns-prefer -s 1.1.1.1:53 -l 0.0.0.0:5367 -c /etc/dns-prefer.conf

# Query through the proxy
nslookup -port=5367 www.google.com 127.0.0.1
```
