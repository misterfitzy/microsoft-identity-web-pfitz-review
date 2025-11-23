# Network Configuration

## DNS Resolution
- `/etc/resolv.conf` → symlink to `/run/systemd/resolve/stub-resolv.conf`
- Nameserver: 127.0.0.53 (systemd-resolved stub)
- Search domain: us-east-1.compute.internal

## Hosts File
- Location: `/etc/hosts`
- Contains localhost entries for IPv4 and IPv6

## Connectivity Test
- Ping to 8.8.8.8: 100% packet loss (network firewall active)
