package parse

import (
	"encoding/xml"
	"strings"
)

// sysmonXMLEvent mirrors the shape of a Sysmon event rendered by
// EventRecord.ToXml(): a System block carrying the timestamp and an EventData
// block of named <Data> elements.
type sysmonXMLEvent struct {
	System struct {
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// SysmonFields parses one Sysmon event XML string into its SystemTime plus a
// map of Data Name → value.
//
// It uses encoding/xml rather than string-scanning for the closing tag, which
// fixes two defects in the old approach: (1) a value containing markup-like
// text was truncated at the first "</Data>" substring, and (2) XML entities
// (&lt; &amp; &quot; …) were never unescaped. A real XML parser handles both,
// so a command line embedded in a ProcessCreate event survives intact.
//
// ok is false when the input is not parseable Sysmon XML; the caller should
// then retain the raw XML for inspection.
func SysmonFields(xmlStr string) (systemTime string, fields map[string]string, ok bool) {
	var ev sysmonXMLEvent
	if err := xml.Unmarshal([]byte(xmlStr), &ev); err != nil {
		return "", nil, false
	}
	fields = make(map[string]string, len(ev.EventData.Data))
	for _, d := range ev.EventData.Data {
		fields[d.Name] = strings.TrimSpace(d.Value)
	}
	return ev.System.TimeCreated.SystemTime, fields, true
}
