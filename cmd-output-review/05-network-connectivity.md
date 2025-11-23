# Network Connectivity Tests

## cURL Test to pypi.org

```bash
runner@github-runner:~$ curl -I https://pypi.org
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: close
Content-Length: 23160
Content-Type: text/html; charset=UTF-8
Date: Sun, 23 Nov 2025 21:39:13 GMT
...
runner@github-runner:~$ 
```

**Result:** ✅ Successfully connected to pypi.org

## Ping Test to 8.8.8.8

```bash
runner@github-runner:~$ ping -c 2 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1055ms
runner@github-runner:~$ 
```

**Result:** ❌ ICMP ping blocked (100% packet loss)

## Summary
- HTTP/HTTPS connectivity: Working
- ICMP (ping) connectivity: Blocked by firewall
