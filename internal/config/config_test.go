package config

import "testing"

func TestValidate_SysmonLogWhitelist(t *testing.T) {
	if err := (&Config{SysmonLog: "Microsoft-Windows-Sysmon/Operational"}).validate(); err != nil {
		t.Errorf("valid sysmon_log rejected: %v", err)
	}
	// An injection-shaped channel name must be rejected before it reaches PowerShell.
	if err := (&Config{SysmonLog: "Sysmon'; Remove-Item C:\\ #"}).validate(); err == nil {
		t.Error("injection-shaped sysmon_log should be rejected")
	}
}

func TestAvailability(t *testing.T) {
	empty := (&Config{}).Availability()
	if empty.ProcessExplorer || empty.Autoruns || empty.VirusTotal || empty.GeoIP {
		t.Error("empty config should report optional tools unavailable")
	}

	set := (&Config{VTAPIKey: "abc", SysmonLog: "X"}).Availability()
	if !set.VirusTotal {
		t.Error("VirusTotal should be available when vt_api_key is set")
	}
	if !set.Sysmon {
		t.Error("Sysmon should be available when sysmon_log is set")
	}
}
