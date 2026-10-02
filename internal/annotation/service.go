package annotation

import (
	"context"
	"sort"
	"strconv"

	"solo-0014-zone-rollout-control/internal/domain"
	"solo-0014-zone-rollout-control/internal/platform"
	"solo-0014-zone-rollout-control/internal/store"
)

type Service struct {
	store *store.Store
	clock platform.Clock
	ids   platform.IDGenerator
}

func New(stateStore *store.Store, clock platform.Clock, ids platform.IDGenerator) *Service {
	return &Service{store: stateStore, clock: clock, ids: ids}
}

// Append adds one immutable entry to the incident timeline. The write only
// extends the annotation log and its request-key index; plans, leases, and
// assessments are read for reference resolution but never modified, so an
// annotation cannot change business state or influence verdicts.
func (s *Service) Append(
	ctx context.Context,
	input domain.AnnotationInput,
) (domain.IncidentAnnotation, error) {
	input = domain.NormalizeAnnotationInput(input)
	if err := domain.ValidateAnnotationInput(input); err != nil {
		return domain.IncidentAnnotation{}, err
	}
	now := s.clock.Now().UTC()
	fingerprint := domain.AnnotationFingerprint(input)
	requestIndex := input.TargetType + "\x00" + input.TargetID + "\x00" + input.RequestKey
	var result domain.IncidentAnnotation
	err := s.store.Write(ctx, func(state *domain.State) error {
		planID, err := resolveTarget(state, input)
		if err != nil {
			return err
		}
		if existingID, exists := state.AnnotationRequestKeys[requestIndex]; exists {
			existing, found := findAnnotation(state, existingID)
			if !found {
				return domain.NewError(domain.CodeStorageFailure, "annotation request index is inconsistent", map[string]any{
					"annotation_id": existingID,
				})
			}
			if existing.PayloadFingerprint != fingerprint {
				return domain.NewError(domain.CodeIdempotencyConflict, "request key was reused with different annotation content", map[string]any{
					"target_type": input.TargetType,
					"target_id":   input.TargetID,
					"request_key": input.RequestKey,
				})
			}
			result = existing
			return nil
		}
		result = domain.IncidentAnnotation{
			ID:                 s.ids.New("ann"),
			TargetType:         domain.AnnotationTargetType(input.TargetType),
			TargetID:           input.TargetID,
			PlanID:             planID,
			Category:           domain.AnnotationCategory(input.Category),
			Body:               input.Body,
			Author:             input.Author,
			RequestKey:         input.RequestKey,
			Sequence:           uint64(len(state.Annotations)) + 1,
			RecordedAt:         now,
			PayloadFingerprint: fingerprint,
		}
		state.Annotations = append(state.Annotations, result)
		state.AnnotationRequestKeys[requestIndex] = result.ID
		store.AddAudit(state, s.ids, "annotation", result.ID, "appended", now, map[string]any{
			"target_type": result.TargetType,
			"target_id":   result.TargetID,
			"plan_id":     result.PlanID,
			"category":    result.Category,
			"author":      result.Author,
			"sequence":    result.Sequence,
		})
		return nil
	})
	return result, err
}

func (s *Service) Get(ctx context.Context, annotationID string) (domain.IncidentAnnotation, error) {
	var result domain.IncidentAnnotation
	err := s.store.Read(ctx, func(state *domain.State) error {
		found, ok := findAnnotation(state, annotationID)
		if !ok {
			return domain.NotFound("annotation", annotationID)
		}
		result = found
		return nil
	})
	return result, err
}

// ListForPlan returns the plan incident timeline in append order. Completed
// plans keep their full timeline readable; annotations never feed back into
// assessment verdicts.
func (s *Service) ListForPlan(
	ctx context.Context,
	planID string,
	category domain.AnnotationCategory,
	targetType domain.AnnotationTargetType,
	limit int,
	cursor string,
) (domain.AnnotationPage, error) {
	after, err := pageBounds(limit, cursor)
	if err != nil {
		return domain.AnnotationPage{}, err
	}
	var page domain.AnnotationPage
	err = s.store.Read(ctx, func(state *domain.State) error {
		if _, ok := state.Plans[planID]; !ok {
			return domain.NotFound("plan", planID)
		}
		items := make([]domain.IncidentAnnotation, 0)
		for _, entry := range state.Annotations {
			if entry.PlanID != planID {
				continue
			}
			if category != "" && entry.Category != category {
				continue
			}
			if targetType != "" && entry.TargetType != targetType {
				continue
			}
			if entry.Sequence <= after {
				continue
			}
			items = append(items, entry)
		}
		page = paginate(items, limit)
		return nil
	})
	return page, err
}

func (s *Service) ListForTarget(
	ctx context.Context,
	targetType domain.AnnotationTargetType,
	targetID string,
	limit int,
	cursor string,
) (domain.AnnotationPage, error) {
	after, err := pageBounds(limit, cursor)
	if err != nil {
		return domain.AnnotationPage{}, err
	}
	var page domain.AnnotationPage
	err = s.store.Read(ctx, func(state *domain.State) error {
		if _, err := targetPlanID(state, targetType, targetID); err != nil {
			return err
		}
		items := make([]domain.IncidentAnnotation, 0)
		for _, entry := range state.Annotations {
			if entry.TargetType != targetType || entry.TargetID != targetID {
				continue
			}
			if entry.Sequence <= after {
				continue
			}
			items = append(items, entry)
		}
		page = paginate(items, limit)
		return nil
	})
	return page, err
}

func resolveTarget(state *domain.State, input domain.AnnotationInput) (string, error) {
	return targetPlanID(state, domain.AnnotationTargetType(input.TargetType), input.TargetID)
}

func targetPlanID(
	state *domain.State,
	targetType domain.AnnotationTargetType,
	targetID string,
) (string, error) {
	switch targetType {
	case domain.AnnotationTargetPlan:
		plan, ok := state.Plans[targetID]
		if !ok {
			return "", domain.NotFound("plan", targetID)
		}
		return plan.ID, nil
	case domain.AnnotationTargetLease:
		lease, ok := state.Leases[targetID]
		if !ok {
			return "", domain.NotFound("lease", targetID)
		}
		return lease.PlanID, nil
	case domain.AnnotationTargetAssessment:
		assessment, ok := state.Assessments[targetID]
		if !ok {
			return "", domain.NotFound("assessment", targetID)
		}
		return assessment.PlanID, nil
	default:
		return "", domain.Validation("annotation target type is not supported", map[string]any{
			"target_type": targetType,
		})
	}
}

func findAnnotation(state *domain.State, annotationID string) (domain.IncidentAnnotation, bool) {
	for _, entry := range state.Annotations {
		if entry.ID == annotationID {
			return entry, true
		}
	}
	return domain.IncidentAnnotation{}, false
}

func pageBounds(limit int, cursor string) (uint64, error) {
	if limit < 1 || limit > 100 {
		return 0, domain.Validation("limit must be between 1 and 100", map[string]any{
			"limit": limit,
		})
	}
	raw, err := platform.DecodeCursor(cursor)
	if err != nil {
		return 0, domain.Validation("cursor is invalid", nil)
	}
	if raw == "" {
		return 0, nil
	}
	after, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, domain.Validation("cursor is invalid", nil)
	}
	return after, nil
}

// paginate orders entries by their monotonic sequence so concurrent appends
// always read back in one deterministic order.
func paginate(items []domain.IncidentAnnotation, limit int) domain.AnnotationPage {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Sequence != items[j].Sequence {
			return items[i].Sequence < items[j].Sequence
		}
		return items[i].ID < items[j].ID
	})
	page := domain.AnnotationPage{}
	page.Meta.Limit = limit
	if len(items) > limit {
		page.Items = append(page.Items, items[:limit]...)
		page.Meta.NextCursor = platform.EncodeCursor(strconv.FormatUint(items[limit-1].Sequence, 10))
		return page
	}
	page.Items = append(page.Items, items...)
	return page
}
