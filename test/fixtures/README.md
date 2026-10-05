# Fixtures

Real traces captured with `npm run trace -- <url> --json` (and `packet path <ip> --json`),
used by the UI tests in `core/derive/*.test.ts`.

One edit was made before committing: the capturing machine's public IPv6 address
(the local end of a TCP connection in `tls13.json`) was replaced with an address
from the documentation range `2001:db8::/32`. Everything else is as captured.
Private (`192.168.*`, `172.16–31.*`) and carrier-NAT (`100.64.*`) addresses
were left alone: they aren't reachable or identifying outside the local network.
