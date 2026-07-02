package parse

import "testing"

func TestNetstat(t *testing.T) {
	const raw = `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:5354         0.0.0.0:0              LISTENING       1234
  TCP    192.168.1.5:52310      140.82.112.21:443      ESTABLISHED     4567
  TCP    [::1]:5432             [::1]:52311            ESTABLISHED     8901
  UDP    0.0.0.0:500            *:*                    5000
`
	conns := Netstat(raw)
	if len(conns) != 4 {
		t.Fatalf("expected 4 connections (header/blank rows dropped), got %d: %+v", len(conns), conns)
	}

	// UDP row must be parsed — it has only 4 fields (no state column). It is
	// stateless (empty status) and its foreign address is the literal "*:*".
	udp := conns[3]
	if udp.Protocol != "UDP" || udp.Status != "" || udp.RemoteAddr != "*:*" || !udp.HasPID || udp.PID != 5000 {
		t.Errorf("UDP row parsed wrong (want stateless, foreign=*:*, pid=5000): %+v", udp)
	}

	est := conns[1]
	if est.Protocol != "TCP" || est.Status != "ESTABLISHED" || est.PID != 4567 || est.RemoteAddr != "140.82.112.21:443" {
		t.Errorf("TCP established row parsed wrong: %+v", est)
	}
}

// TestNetstatLocaleAndMalformedPID proves PID attribution survives a localised
// state column and that a non-numeric PID is not silently coerced to 0.
func TestNetstatLocaleAndMalformedPID(t *testing.T) {
	const raw = `  TCP    10.0.0.1:445    10.0.0.2:1000    HERGESTELLT    2222
  TCP    1.2.3.4:80      5.6.7.8:90       ESTABLISHED    notapid`
	conns := Netstat(raw)
	if len(conns) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(conns))
	}
	if !conns[0].HasPID || conns[0].PID != 2222 {
		t.Errorf("localised-state row lost its PID: %+v", conns[0])
	}
	if conns[1].HasPID {
		t.Errorf("non-numeric PID must not be attributed (would pollute as PID 0): %+v", conns[1])
	}
}

func TestRemoteIP(t *testing.T) {
	cases := map[string]string{
		"140.82.112.21:443": "140.82.112.21",
		"[::1]:52311":       "::1",
		"[fe80::1]:80":      "fe80::1",
		"::1":               "::1", // bare IPv6, no port
		"[::1":              "::1", // malformed bracket — best effort
		"*":                 "",
		"":                  "",
		"0.0.0.0:0":         "0.0.0.0",
	}
	for in, want := range cases {
		if got := RemoteIP(in); got != want {
			t.Errorf("RemoteIP(%q) = %q, want %q", in, got, want)
		}
	}
}
