package domain

import (
	"net"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxZoneRunes       = 253
	MaxAuthorityRunes  = 253
	MaxNodeNameRunes   = 180
	MaxRegionRunes     = 48
	MinRequestKeyRunes = 8
	MaxRequestKeyRunes = 64
	MaxEntries         = 500
	MaxActorRunes      = 120
	MaxAnnotationRunes = 4000
)

type PlanCreateInput struct {
	Zone                string  `json:"zone"`
	MinimumSuccessRatio float64 `json:"minimum_success_ratio"`
	MaximumLatencyMS    int     `json:"maximum_latency_ms"`
	ExpectedNodes       int     `json:"expected_nodes"`
}

type RevisionCreateInput struct {
	Serial    uint32      `json:"serial"`
	Authority string      `json:"authority"`
	Entries   []ZoneEntry `json:"entries"`
}

type NodeCreateInput struct {
	NodeName   string `json:"node_name"`
	Region     string `json:"region"`
	Quarantine bool   `json:"quarantine"`
}

type LeaseInput struct {
	RequestKey   string `json:"request_key"`
	Region       string `json:"region"`
	LeaseSeconds int    `json:"lease_seconds"`
	MaxNodes     int    `json:"max_nodes"`
}

type ProbeInput struct {
	RequestKey     string    `json:"request_key"`
	Success        bool      `json:"success"`
	ObservedSerial uint32    `json:"observed_serial"`
	LatencyMS      int       `json:"latency_ms"`
	ObservedAt     time.Time `json:"observed_at"`
}

type AssessmentInput struct {
	RequestKey string `json:"request_key"`
}

type AnnotationInput struct {
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Category   string `json:"category"`
	Body       string `json:"body"`
	Actor      string `json:"actor"`
	RequestKey string `json:"request_key"`
}

func NormalizePlanInput(input PlanCreateInput) PlanCreateInput {
	input.Zone = canonicalName(input.Zone)
	return input
}

func ValidatePlanInput(input PlanCreateInput) error {
	input = NormalizePlanInput(input)
	details := make(map[string]any)
	if err := validateCanonicalName(input.Zone); err != nil {
		details["zone"] = err.Error()
	}
	if input.MinimumSuccessRatio < 0 || input.MinimumSuccessRatio > 1 {
		details["minimum_success_ratio"] = "must be between 0 and 1"
	}
	if input.MaximumLatencyMS < 1 || input.MaximumLatencyMS > 600000 {
		details["maximum_latency_ms"] = "must be between 1 and 600000"
	}
	if input.ExpectedNodes < 1 || input.ExpectedNodes > 500 {
		details["expected_nodes"] = "must be between 1 and 500"
	}
	if len(details) > 0 {
		return Validation("plan input is invalid", details)
	}
	return nil
}

func NormalizeRevisionInput(input RevisionCreateInput) (RevisionCreateInput, error) {
	input.Authority = canonicalName(input.Authority)
	entries := make([]ZoneEntry, 0, len(input.Entries))
	for _, entry := range input.Entries {
		owner := canonicalName(entry.Owner)
		entryType := EntryType(strings.ToUpper(strings.TrimSpace(string(entry.Type))))
		value := strings.TrimSpace(entry.Value)
		switch entryType {
		case EntryA:
			parsed := net.ParseIP(value)
			if parsed == nil || parsed.To4() == nil {
				return RevisionCreateInput{}, Validation("zone entry is invalid", map[string]any{
					"owner": owner,
					"type":  entryType,
					"value": "must be a valid IPv4 address",
				})
			}
			value = parsed.To4().String()
		case EntryAAAA:
			parsed := net.ParseIP(value)
			if parsed == nil || parsed.To4() != nil {
				return RevisionCreateInput{}, Validation("zone entry is invalid", map[string]any{
					"owner": owner,
					"type":  entryType,
					"value": "must be a valid IPv6 address",
				})
			}
			value = parsed.String()
		case EntryCNAME:
			value = canonicalName(value)
			if err := validateCanonicalName(value); err != nil {
				return RevisionCreateInput{}, Validation("zone entry is invalid", map[string]any{
					"owner": owner,
					"type":  entryType,
					"value": err.Error(),
				})
			}
		default:
			return RevisionCreateInput{}, Validation("zone entry is invalid", map[string]any{
				"owner": owner,
				"type":  entry.Type,
				"value": "type must be A, AAAA, or CNAME",
			})
		}
		if err := validateCanonicalName(owner); err != nil {
			return RevisionCreateInput{}, Validation("zone entry is invalid", map[string]any{
				"owner": owner,
				"value": err.Error(),
			})
		}
		entries = append(entries, ZoneEntry{Owner: owner, Type: entryType, Value: value})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Owner != entries[j].Owner {
			return entries[i].Owner < entries[j].Owner
		}
		if entries[i].Type != entries[j].Type {
			return entries[i].Type < entries[j].Type
		}
		return entries[i].Value < entries[j].Value
	})
	for index := 1; index < len(entries); index++ {
		if entries[index] == entries[index-1] {
			return RevisionCreateInput{}, Validation("zone entry is duplicated", map[string]any{
				"owner": entries[index].Owner,
				"type":  entries[index].Type,
				"value": entries[index].Value,
			})
		}
	}
	input.Entries = entries
	return input, nil
}

func ValidateRevisionInput(input RevisionCreateInput) error {
	if input.Serial == 0 {
		return Validation("revision input is invalid", map[string]any{
			"serial": "must be greater than zero",
		})
	}
	if err := validateCanonicalName(input.Authority); err != nil {
		return Validation("revision input is invalid", map[string]any{
			"authority": err.Error(),
		})
	}
	if len(input.Entries) < 1 || len(input.Entries) > MaxEntries {
		return Validation("revision input is invalid", map[string]any{
			"entries": "must contain between 1 and 500 items",
		})
	}
	return nil
}

func ValidateNodeInput(input NodeCreateInput, now time.Time) error {
	input.NodeName = canonicalName(input.NodeName)
	input.Region = strings.TrimSpace(strings.ToLower(input.Region))
	details := make(map[string]any)
	if err := validateCanonicalName(input.NodeName); err != nil {
		details["node_name"] = err.Error()
	}
	if count := utf8.RuneCountInString(input.Region); count < 2 || count > MaxRegionRunes {
		details["region"] = "must contain between 2 and 48 characters"
	}
	if len(details) > 0 {
		return Validation("node input is invalid", details)
	}
	return nil
}

func NormalizeNodeInput(input NodeCreateInput) NodeCreateInput {
	input.NodeName = canonicalName(input.NodeName)
	input.Region = strings.TrimSpace(strings.ToLower(input.Region))
	return input
}

func ValidateLeaseInput(input LeaseInput) error {
	input.RequestKey = strings.TrimSpace(input.RequestKey)
	input.Region = strings.TrimSpace(strings.ToLower(input.Region))
	details := make(map[string]any)
	if err := validateRequestKey(input.RequestKey); err != nil {
		details["request_key"] = err.Error()
	}
	if count := utf8.RuneCountInString(input.Region); count > MaxRegionRunes {
		details["region"] = "must be at most 48 characters"
	}
	if input.LeaseSeconds < 30 || input.LeaseSeconds > 86400 {
		details["lease_seconds"] = "must be between 30 and 86400"
	}
	if input.MaxNodes < 1 || input.MaxNodes > 100 {
		details["max_nodes"] = "must be between 1 and 100"
	}
	if len(details) > 0 {
		return Validation("lease input is invalid", details)
	}
	return nil
}

func ValidateProbeInput(input ProbeInput, now time.Time) error {
	input.RequestKey = strings.TrimSpace(input.RequestKey)
	details := make(map[string]any)
	if err := validateRequestKey(input.RequestKey); err != nil {
		details["request_key"] = err.Error()
	}
	if input.LatencyMS < 0 || input.LatencyMS > 600000 {
		details["latency_ms"] = "must be between 0 and 600000"
	}
	if input.ObservedAt.IsZero() {
		details["observed_at"] = "is required"
	} else if input.ObservedAt.After(now.Add(5 * time.Minute)) {
		details["observed_at"] = "cannot be more than five minutes in the future"
	}
	if len(details) > 0 {
		return Validation("probe input is invalid", details)
	}
	return nil
}

func ValidateAssessmentInput(input AssessmentInput) error {
	input.RequestKey = strings.TrimSpace(input.RequestKey)
	if err := validateRequestKey(input.RequestKey); err != nil {
		return Validation("assessment input is invalid", map[string]any{
			"request_key": err.Error(),
		})
	}
	return nil
}

// NormalizeAnnotationInput trims the structured fields but preserves the
// annotation body verbatim, apart from trimming surrounding whitespace.
func NormalizeAnnotationInput(input AnnotationInput) AnnotationInput {
	input.TargetType = strings.TrimSpace(strings.ToLower(input.TargetType))
	input.TargetID = strings.TrimSpace(input.TargetID)
	input.Category = strings.TrimSpace(strings.ToLower(input.Category))
	input.Body = strings.TrimSpace(input.Body)
	input.Actor = strings.TrimSpace(input.Actor)
	input.RequestKey = strings.TrimSpace(input.RequestKey)
	return input
}

func ValidateAnnotationInput(input AnnotationInput) error {
	details := make(map[string]any)
	switch AnnotationTargetType(input.TargetType) {
	case AnnotationTargetPlan, AnnotationTargetLease, AnnotationTargetAssessment:
	default:
		details["target_type"] = "must be one of plan, lease, assessment"
	}
	if input.TargetID == "" {
		details["target_id"] = "is required"
	}
	switch AnnotationCategory(input.Category) {
	case AnnotationCategoryObservation,
		AnnotationCategoryRootCause,
		AnnotationCategoryAction,
		AnnotationCategoryDecision,
		AnnotationCategoryEvidence:
	default:
		details["category"] = "must be one of observation, root_cause, action, decision, evidence"
	}
	if bodyCount := utf8.RuneCountInString(input.Body); bodyCount < 1 || bodyCount > MaxAnnotationRunes {
		details["body"] = "must contain between 1 and 4000 characters"
	} else if containsControlRune(input.Body) {
		details["body"] = "must not contain control characters"
	}
	if actorCount := utf8.RuneCountInString(input.Actor); actorCount < 1 || actorCount > MaxActorRunes {
		details["actor"] = "must contain between 1 and 120 characters"
	} else if containsControlRune(input.Actor) {
		details["actor"] = "must not contain control characters"
	}
	if input.RequestKey != "" {
		if err := validateRequestKey(input.RequestKey); err != nil {
			details["request_key"] = err.Error()
		}
	}
	if len(details) > 0 {
		return Validation("annotation input is invalid", details)
	}
	return nil
}

// containsControlRune reports whether value holds an ASCII control character
// other than tab, newline, or carriage return.
func containsControlRune(value string) bool {
	for _, r := range value {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return true
		}
		if r == 0x7f {
			return true
		}
	}
	return false
}

func validateRequestKey(value string) error {
	count := utf8.RuneCountInString(value)
	if count < MinRequestKeyRunes || count > MaxRequestKeyRunes {
		return Validation("must contain between 8 and 64 characters", nil)
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		if r == '-' || r == '_' {
			continue
		}
		return Validation("may contain only letters, digits, hyphens, and underscores", nil)
	}
	return nil
}

func canonicalName(value string) string {
	return strings.TrimSuffix(strings.TrimSpace(strings.ToLower(value)), ".")
}

func validateCanonicalName(value string) error {
	if value == "" {
		return Validation("is required", nil)
	}
	if len(value) > MaxZoneRunes {
		return Validation("is too long", nil)
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 {
			return Validation("contains an invalid label length", nil)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return Validation("labels cannot start or end with a hyphen", nil)
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
				continue
			}
			return Validation("contains unsupported characters", nil)
		}
	}
	return nil
}
