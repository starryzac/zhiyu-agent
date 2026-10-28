package domain

import "time"

// TemplateDateRange is a validated, call-local snapshot of immutable template
// date bounds. It confers no state, USER, execution or bank authority.
// Prepare again for every forecast/protection call; there is no shared cache.
type TemplateDateRange struct {
	zone      *time.Location
	start     time.Time
	firstDate string
	end       *time.Time
}

func PrepareTemplateDateRange(version TemplateVersion, timezone string) (TemplateDateRange, error) {
	zone, err := TemplateLocation(timezone)
	if err != nil {
		return TemplateDateRange{}, err
	}
	// Keep strict canonical/hash/unknown-field rejection in Compiled.Decode.
	start, end, err := TemplateValidity(version.Compiled, version.ConfirmedAt, timezone)
	if err != nil {
		return TemplateDateRange{}, err
	}
	if start.Before(version.ConfirmedAt) {
		start = version.ConfirmedAt
	}
	return TemplateDateRange{zone: zone, start: start, firstDate: start.In(zone).Format("2006-01-02"), end: end}, nil
}

func (r TemplateDateRange) Start() time.Time { return r.start }

// ActiveOnDate retains TemplateActiveOnDate's natural-date semantics. Policy
// state/current/confirmation validation remains with the owning calculation.
func (r TemplateDateRange) ActiveOnDate(date string) (bool, error) {
	day, err := TemplateDate(date)
	if err != nil {
		return false, err
	}
	return r.activeOnParsedDate(date, day)
}

// ActiveOnDateScoped changes only call-local successful date parsing. The
// concrete scope cannot supply an unchecked parser or cache an active verdict.
func (r TemplateDateRange) ActiveOnDateScoped(date string, scope *TemplateDateParseScope) (bool, error) {
	day, err := scope.parse(date)
	if err != nil {
		return false, err
	}
	return r.activeOnParsedDate(date, day)
}

func (r TemplateDateRange) activeOnParsedDate(date string, day time.Time) (bool, error) {
	if r.zone == nil {
		return false, ErrTemplate
	}
	local := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, r.zone)
	return date >= r.firstDate && (r.end == nil || local.Before(*r.end)), nil
}
