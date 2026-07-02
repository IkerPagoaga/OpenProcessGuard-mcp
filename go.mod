module processguard-mcp

go 1.22

// Build with a patched toolchain: go1.25.11 resolves 8 standard-library
// advisories (crypto/x509, crypto/tls, net/http, net/url, net/textproto)
// reachable via the VirusTotal HTTPS client. Verified clean by govulncheck.
toolchain go1.25.11

require (
	github.com/oschwald/geoip2-golang v1.13.0
	github.com/shirou/gopsutil/v3 v3.23.12
)

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	golang.org/x/sys v0.20.0 // indirect
)
