package store

import (
	"fmt"
	"sort"

	"solo-0014-zone-rollout-control/internal/domain"
)

const schemaVersion = 1

func blankState() domain.State {
	return normalize(domain.State{})
}

func normalize(state domain.State) domain.State {
	if state.SchemaVersion == 0 {
		state.SchemaVersion = schemaVersion
	}
	if state.Plans == nil {
		state.Plans = make(map[string]domain.RolloutPlan)
	}
	if state.Revisions == nil {
		state.Revisions = make(map[string]domain.ZoneRevision)
	}
	if state.Nodes == nil {
		state.Nodes = make(map[string]domain.ResolverNode)
	}
	if state.Leases == nil {
		state.Leases = make(map[string]domain.NodeLease)
	}
	if state.LeaseGroups == nil {
		state.LeaseGroups = make(map[string]domain.LeaseGroup)
	}
	if state.Probes == nil {
		state.Probes = make(map[string]domain.Probe)
	}
	if state.Assessments == nil {
		state.Assessments = make(map[string]domain.RolloutAssessment)
	}
	if state.LeaseRequestKeys == nil {
		state.LeaseRequestKeys = make(map[string]string)
	}
	if state.AssessmentRequestKeys == nil {
		state.AssessmentRequestKeys = make(map[string]string)
	}
	if state.AuditEvents == nil {
		state.AuditEvents = []domain.AuditEvent{}
	}
	if state.Annotations == nil {
		state.Annotations = []domain.IncidentAnnotation{}
	}
	if state.AnnotationRequestKeys == nil {
		state.AnnotationRequestKeys = make(map[string]string)
	}
	return state
}

// reconcileTimeline restores append-only timeline invariants after a snapshot
// is loaded: entries stay ordered by their commit sequence, the sequence
// counter covers the highest entry, and every annotation reference is closed.
// It returns an error instead of silently dropping history.
func reconcileTimeline(state *domain.State) error {
	annotations := state.Annotations
	sort.SliceStable(annotations, func(i, j int) bool {
		if annotations[i].Sequence != annotations[j].Sequence {
			return annotations[i].Sequence < annotations[j].Sequence
		}
		return annotations[i].ID < annotations[j].ID
	})
	seenSequence := make(map[uint64]string, len(annotations))
	seenID := make(map[string]struct{}, len(annotations))
	var highest uint64
	for index, annotation := range annotations {
		if annotation.Sequence == 0 {
			return fmt.Errorf("annotation %s has no sequence", annotation.ID)
		}
		if otherID, duplicate := seenSequence[annotation.Sequence]; duplicate {
			return fmt.Errorf("annotations %s and %s share sequence %d", otherID, annotation.ID, annotation.Sequence)
		}
		seenSequence[annotation.Sequence] = annotation.ID
		if annotation.Sequence > highest {
			highest = annotation.Sequence
		}
		if _, duplicate := seenID[annotation.ID]; duplicate {
			return fmt.Errorf("duplicate annotation id %s", annotation.ID)
		}
		seenID[annotation.ID] = struct{}{}
		planID, err := resolveAnnotationPlan(state, annotation.TargetType, annotation.TargetID)
		if err != nil {
			return fmt.Errorf("annotation %s is not closed: %w", annotation.ID, err)
		}
		if annotation.PlanID != planID {
			return fmt.Errorf("annotation %s belongs to plan %s but points to plan %s", annotation.ID, planID, annotation.PlanID)
		}
		if index > 0 {
			prev := annotations[index-1].Sequence
			if prev >= annotation.Sequence {
				return fmt.Errorf("annotation sequence ordering broke at %d", annotation.Sequence)
			}
		}
	}
	if state.AnnotationSequence < highest {
		state.AnnotationSequence = highest
	}

	// Rebuild the idempotency index from the immutable entries so a replay
	// after restart still returns the original annotation.
	indexed := make(map[string]string, len(annotations))
	for _, annotation := range annotations {
		if annotation.RequestKey == "" {
			continue
		}
		key := AnnotationRequestIndex(annotation.TargetType, annotation.TargetID, annotation.RequestKey)
		if existingID, exists := indexed[key]; exists && existingID != annotation.ID {
			return fmt.Errorf("request key %q reused by annotations %s and %s", key, existingID, annotation.ID)
		}
		if storedID, exists := state.AnnotationRequestKeys[key]; exists && storedID != annotation.ID {
			return fmt.Errorf("annotation request index for %q points to %s, expected %s", key, storedID, annotation.ID)
		}
		indexed[key] = annotation.ID
	}
	for key, annotationID := range state.AnnotationRequestKeys {
		if _, ok := seenID[annotationID]; !ok {
			return fmt.Errorf("annotation request index for %q points to missing annotation %s", key, annotationID)
		}
	}
	state.AnnotationRequestKeys = indexed
	state.Annotations = annotations
	return nil
}

func resolveAnnotationPlan(
	state *domain.State,
	targetType domain.AnnotationTargetType,
	targetID string,
) (string, error) {
	switch targetType {
	case domain.AnnotationTargetPlan:
		target, ok := state.Plans[targetID]
		if !ok {
			return "", fmt.Errorf("referenced plan %s does not exist", targetID)
		}
		return target.ID, nil
	case domain.AnnotationTargetLease:
		target, ok := state.Leases[targetID]
		if !ok {
			return "", fmt.Errorf("referenced lease %s does not exist", targetID)
		}
		return target.PlanID, nil
	case domain.AnnotationTargetAssessment:
		target, ok := state.Assessments[targetID]
		if !ok {
			return "", fmt.Errorf("referenced assessment %s does not exist", targetID)
		}
		return target.PlanID, nil
	default:
		return "", fmt.Errorf("unknown annotation target type %q", targetType)
	}
}

// AnnotationRequestIndex builds the idempotency scope for an annotation replay:
// request keys are unique per target object.
func AnnotationRequestIndex(
	targetType domain.AnnotationTargetType,
	targetID string,
	requestKey string,
) string {
	return string(targetType) + "\x00" + targetID + "\x00" + requestKey
}

// ResolveAnnotationPlan returns the plan a target object belongs to, or an
// error when the target does not exist. It enforces that annotation
// references are closed at write time.
func ResolveAnnotationPlan(
	state *domain.State,
	targetType domain.AnnotationTargetType,
	targetID string,
) (string, error) {
	return resolveAnnotationPlan(state, targetType, targetID)
}
