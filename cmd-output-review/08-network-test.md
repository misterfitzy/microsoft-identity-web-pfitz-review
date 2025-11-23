# Network Connectivity Tests

## Ping Test (8.8.8.8)

```bash
runner@github-runner:~$ export FIREWALL_RULESET_CONTENT=""
runner@github-runner:~$ export COPILOT_AGENT_FIREWALL_RULESET_ALLOW_LIST=""
runner@github-runner:~$ ping -c 2 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1055ms
```

**Result:** 100% packet loss - ICMP traffic appears to be blocked.

## cURL Test (pypi.org)

```bash
runner@github-runner:~$ curl -I https://pypi.org
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: close
Content-Length: 23160
Content-Security-Policy: base-uri 'self'; connect-src 'self' https://api.github.com/repos/ ...
Content-Type: text/html; charset=UTF-8
Date: Sun, 23 Nov 2025 21:39:13 GMT
Etag: "lqUrLHIkoZC0zTWLLrDzkQ"
```

**Result:** HTTPS connection successful - HTTP/HTTPS traffic is allowed.
