package annotation

import (
	"context"
	"strconv"

	"solo-0014-zone-rollout-control/internal/domain"
	"solo-0014-zone-rollout-control/internal/platform"
	"solo-0014-zone-rollout-control/internal/store"
)

// AppendResult reports whether an append created a new timeline entry or
// returned an existing one through idempotent replay.
type AppendResult struct {
	Annotation domain.IncidentAnnotation
	Created    bool
}

type Service struct {
	store *store.Store
	clock platform.Clock
	ids   platform.IDGenerator
}

func New(stateStore *store.Store, clock platform.Clock, ids platform.IDGenerator) *Service {
	return &Service{store: stateStore, clock: clock, ids: ids}
}

// Append adds one immutable entry. It only touches the annotation timeline and
// its own sequence counter; plans, leases, and assessments are read but never
// modified. The whole decision happens under the store write lock, so
// concurrent appends commit in one deterministic sequence order.
func (s *Service) Append(
	ctx context.Context,
	input domain.AnnotationInput,
	origin Origin,
) (AppendResult, error) {
	input = domain.NormalizeAnnotationInput(input)
	if err := domain.ValidateAnnotationInput(input); err != nil {
		return AppendResult{}, err
	}
	targetType := domain.AnnotationTargetType(input.TargetType)
	fingerprint := domain.AnnotationFingerprint(input)
	requestIndex := ""
	if input.RequestKey != "" {
		requestIndex = store.AnnotationRequestIndex(targetType, input.TargetID, input.RequestKey)
	}
	now := s.clock.Now().UTC()
	var result AppendResult

	err := s.store.Write(ctx, func(state *domain.State) error {
		// The referenced object must exist before history is recorded.
		planID, err := store.ResolveAnnotationPlan(state, targetType, input.TargetID)
		if err != nil {
			return domain.NotFound(string(targetType), input.TargetID)
		}
		if requestIndex != "" {
			if existingID, exists := state.AnnotationRequestKeys[requestIndex]; exists {
				existing, found := lookupAnnotation(state, existingID)
				if !found {
					return domain.NewError(domain.CodeStorageFailure, "annotation index is inconsistent", map[string]any{
						"annotation_id": existingID,
					})
				}
				if existing.Fingerprint != fingerprint {
					return domain.NewError(domain.CodeIdempotencyConflict, "request key was reused with different annotation content", map[string]any{
						"target_type": targetType,
						"target_id":   input.TargetID,
						"request_key": input.RequestKey,
					})
				}
				result = AppendResult{Annotation: existing, Created: false}
				return nil
			}
		}

		state.AnnotationSequence++
		created := domain.IncidentAnnotation{
			ID:          s.ids.New("ntt"),
			Sequence:    state.AnnotationSequence,
			TargetType:  targetType,
			TargetID:    input.TargetID,
			PlanID:      planID,
			Category:    domain.AnnotationCategory(input.Category),
			Body:        input.Body,
			Actor:       input.Actor,
			RecordedAt:  now,
			Source:      origin.Source,
			RequestID:   origin.RequestID,
			RequestKey:  input.RequestKey,
			Fingerprint: fingerprint,
		}
		state.Annotations = append(state.Annotations, created)
		if requestIndex != "" {
			state.AnnotationRequestKeys[requestIndex] = created.ID
		}
		store.AddAudit(state, s.ids, "annotation", created.ID, "appended", now, map[string]any{
			"target_type": created.TargetType,
			"target_id":   created.TargetID,
			"plan_id":     created.PlanID,
			"category":    created.Category,
			"sequence":    created.Sequence,
		})
		result = AppendResult{Annotation: created, Created: true}
		return nil
	})
	return result, err
}

// Get returns one timeline entry by id.
func (s *Service) Get(ctx context.Context, annotationID string) (domain.IncidentAnnotation, error) {
	var result domain.IncidentAnnotation
	err := s.store.Read(ctx, func(state *domain.State) error {
		for _, annotation := range state.Annotations {
			if annotation.ID == annotationID {
				result = annotation
				return nil
			}
		}
		return domain.NotFound("annotation", annotationID)
	})
	return result, err
}

// List returns the whole timeline, or the portion belonging to one plan, in
// commit sequence order. Paging continues with the opaque sequence cursor.
func (s *Service) List(
	ctx context.Context,
	planID string,
	limit int,
	cursor string,
) (domain.AnnotationPage, error) {
	if limit < 1 || limit > 100 {
		return domain.AnnotationPage{}, domain.Validation("limit must be between 1 and 100", map[string]any{
			"limit": limit,
		})
	}
	after := uint64(0)
	if cursor != "" {
		parsed, err := platform.DecodeCursor(cursor)
		if err != nil {
			return domain.AnnotationPage{}, domain.Validation("cursor is invalid", nil)
		}
		value, err := strconv.ParseUint(parsed, 10, 64)
		if err != nil || value == 0 {
			return domain.AnnotationPage{}, domain.Validation("cursor is invalid", nil)
		}
		after = value
	}
	var page domain.AnnotationPage
	err := s.store.Read(ctx, func(state *domain.State) error {
		if planID != "" {
			if _, ok := state.Plans[planID]; !ok {
				return domain.NotFound("plan", planID)
			}
		}
		items := make([]domain.IncidentAnnotation, 0, len(state.Annotations))
		for _, annotation := range state.Annotations {
			if annotation.Sequence <= after {
				continue
			}
			if planID != "" && annotation.PlanID != planID {
				continue
			}
			items = append(items, annotation)
		}
		// Reconcile keeps the slice sorted; sort again defensively so reads
		// always follow the deterministic commit order.
		sortBySequence(items)
		page.Meta.Limit = limit
		if len(items) > limit {
			page.Items = append(page.Items, items[:limit]...)
			page.Meta.NextCursor = platform.EncodeCursor(strconv.FormatUint(items[limit-1].Sequence, 10))
			return nil
		}
		page.Items = append(page.Items, items...)
		return nil
	})
	return page, err
}

// ListForTarget returns annotations attached directly to one lease,
// assessment, or plan, after confirming the target still exists.
func (s *Service) ListForTarget(
	ctx context.Context,
	targetType domain.AnnotationTargetType,
	targetID string,
) ([]domain.IncidentAnnotation, error) {
	items := make([]domain.IncidentAnnotation, 0)
	err := s.store.Read(ctx, func(state *domain.State) error {
		if _, err := store.ResolveAnnotationPlan(state, targetType, targetID); err != nil {
			return domain.NotFound(string(targetType), targetID)
		}
		for _, annotation := range state.Annotations {
			if annotation.TargetType == targetType && annotation.TargetID == targetID {
				items = append(items, annotation)
			}
		}
		sortBySequence(items)
		return nil
	})
	return items, err
}

func lookupAnnotation(state *domain.State, id string) (domain.IncidentAnnotation, bool) {
	for _, annotation := range state.Annotations {
		if annotation.ID == id {
			return annotation, true
		}
	}
	return domain.IncidentAnnotation{}, false
}

func sortBySequence(items []domain.IncidentAnnotation) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j-1].Sequence > items[j].Sequence; j-- {
			items[j-1], items[j] = items[j], items[j-1]
		}
	}
}
