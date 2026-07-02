package parse

import (
	"encoding/csv"
	"strconv"
	"strings"
)

// AutorunRow is one parsed row of `autorunsc -c` output, with columns resolved
// by header name so the parser survives column-order changes across autorunsc
// versions.
type AutorunRow struct {
	EntryLocation string
	EntryName     string
	Description   string
	Signer        string
	Company       string
	ImagePath     string
	LaunchString  string
	SHA256        string
	VTDetections  int
	VTTotal       int
	// SignerKnown is false when the CSV had no Signer column at all. Callers
	// must NOT treat an absent signer column as "unsigned" — that produced a
	// wall of false-positive UNSIGNED flags. Absent column ⇒ unknown, not unsigned.
	SignerKnown bool
	// VTKnown is true only when a well-formed "N/M" VirusTotal score was parsed.
	VTKnown bool
}

const colNotFound = -1

type autorunsColIdx struct {
	entryLocation, entry, description, signer, company int
	imagePath, launchString, vtDetection, sha256       int
}

// AutorunsCSV parses autorunsc CSV output using encoding/csv, which correctly
// handles RFC-4180 quoting — including the escaped-quote form `""` inside a
// quoted field that the previous hand-rolled splitter mangled.
func AutorunsCSV(raw string) ([]AutorunRow, error) {
	r := csv.NewReader(strings.NewReader(raw))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1 // rows vary in length across versions

	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	var header []string
	dataStart := 0
	for i, rec := range records {
		if !isBlankRecord(rec) {
			header = rec
			dataStart = i + 1
			break
		}
	}
	if header == nil {
		return nil, nil
	}

	idx := buildAutorunsColIdx(header)

	var rows []AutorunRow
	for _, rec := range records[dataStart:] {
		if isBlankRecord(rec) {
			continue
		}
		row := AutorunRow{
			EntryLocation: colAt(rec, idx.entryLocation),
			EntryName:     colAt(rec, idx.entry),
			Description:   colAt(rec, idx.description),
			Company:       colAt(rec, idx.company),
			ImagePath:     colAt(rec, idx.imagePath),
			LaunchString:  colAt(rec, idx.launchString),
			SHA256:        strings.ToLower(strings.TrimSpace(colAt(rec, idx.sha256))),
			SignerKnown:   idx.signer != colNotFound,
		}
		if row.SignerKnown {
			row.Signer = strings.TrimSpace(colAt(rec, idx.signer))
		}
		if idx.vtDetection != colNotFound {
			if det, total, ok := ParseVTScore(colAt(rec, idx.vtDetection)); ok {
				row.VTDetections, row.VTTotal, row.VTKnown = det, total, true
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// ParseVTScore parses a VirusTotal "N/M" score with checked conversions.
// A malformed value (e.g. "5-72", "", "n/a") returns ok=false rather than
// silently yielding 0/0 and hiding a real detection.
func ParseVTScore(s string) (detections, total int, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(s), "/", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	det, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	tot, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return det, tot, true
}

func buildAutorunsColIdx(header []string) autorunsColIdx {
	idx := autorunsColIdx{
		entryLocation: colNotFound, entry: colNotFound, description: colNotFound,
		signer: colNotFound, company: colNotFound, imagePath: colNotFound,
		launchString: colNotFound, vtDetection: colNotFound, sha256: colNotFound,
	}
	for i, col := range header {
		lower := strings.ToLower(strings.TrimSpace(col))
		switch {
		case strings.Contains(lower, "entry location"):
			idx.entryLocation = i
		case (lower == "entry" || strings.HasPrefix(lower, "entry")) &&
			idx.entry == colNotFound && !strings.Contains(lower, "location"):
			idx.entry = i
		case strings.Contains(lower, "description"):
			idx.description = i
		case strings.Contains(lower, "signer"):
			idx.signer = i
		case strings.Contains(lower, "company"):
			idx.company = i
		case strings.Contains(lower, "image path"):
			idx.imagePath = i
		case strings.Contains(lower, "launch string"):
			idx.launchString = i
		case strings.Contains(lower, "vt detection"):
			idx.vtDetection = i
		case strings.Contains(lower, "sha-256") || lower == "sha256":
			idx.sha256 = i
		}
	}
	return idx
}

func colAt(cols []string, i int) string {
	if i == colNotFound || i < 0 || i >= len(cols) {
		return ""
	}
	return strings.TrimSpace(cols[i])
}

func isBlankRecord(rec []string) bool {
	for _, f := range rec {
		if strings.TrimSpace(f) != "" {
			return false
		}
	}
	return true
}
