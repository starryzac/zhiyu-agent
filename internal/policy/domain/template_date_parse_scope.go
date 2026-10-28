package domain

import "time"

type templateDateParseEntry struct {
	date  string
	day   time.Time
	valid bool
}

// TemplateDateParseScope owns at most two successful canonical UTC date parses
// within one calculation. Its zero value is ready. Do not share it between
// calculations or goroutines; it contains no range, policy or authority verdict.
type TemplateDateParseScope struct {
	entries [2]templateDateParseEntry
	next    uint8
}

func (scope *TemplateDateParseScope) parse(date string) (time.Time, error) {
	if scope == nil {
		return TemplateDate(date)
	}
	for _, entry := range scope.entries {
		if entry.valid && entry.date == date {
			return entry.day, nil
		}
	}
	day, err := TemplateDate(date)
	if err != nil {
		return day, err
	}
	scope.entries[scope.next] = templateDateParseEntry{date: date, day: day, valid: true}
	scope.next = (scope.next + 1) % 2
	return day, nil
}
