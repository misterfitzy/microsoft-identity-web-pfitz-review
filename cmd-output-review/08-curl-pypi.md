# curl -I https://pypi.org

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
Permissions-Policy: publickey-credentials-create=(self),publickey-credentials-get=(self)...
```

**Result:** Successfully connected to pypi.org (HTTP 200 OK)
