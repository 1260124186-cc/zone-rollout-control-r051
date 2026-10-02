package workflowprobe

import (
	"fmt"
	"net/http"
	"sync"

	"solo-0014-zone-rollout-control/internal/domain"
)

func runIncidentAnnotations() error {
	harness, err := newHarness()
	if err != nil {
		return err
	}
	defer harness.close()

	if _, err := enrollNode(harness, "resolver-incident-01", "east"); err != nil {
		return err
	}
	plan, revision, err := createActivePlan(harness, "incident.example", 5001, 1, 1, 40)
	if err != nil {
		return err
	}
	group, err := allocate(harness, plan.ID, "incident-lease-01", "east", 1)
	if err != nil {
		return err
	}
	leaseID := group.LeaseIDs[0]
	if _, err := submitProbe(harness, leaseID, "incident-probe-01", true, revision.Serial, 10); err != nil {
		return err
	}
	var assessment domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "incident-assess-1",
	}, &assessment); err != nil {
		return err
	}
	if assessment.Verdict != domain.VerdictConsistent {
		return ensure(false, "baseline assessment was not consistent")
	}
	var before domain.RolloutPlan
	if err := harness.call(http.MethodGet, "/v1/plans/"+plan.ID, nil, &before); err != nil {
		return err
	}

	planNote, err := annotate(harness, domain.AnnotationInput{
		TargetType: "plan",
		TargetID:   plan.ID,
		Category:   "observation",
		Body:       "edge resolvers reported stale serial during the rollout",
		Author:     "oncall.alice",
		RequestKey: "incident-note-01",
	})
	if err != nil {
		return err
	}
	if planNote.Sequence != 1 || planNote.PlanID != plan.ID || planNote.RecordedAt.IsZero() {
		return ensure(false, "plan annotation did not record sequence, plan reference, and time")
	}
	leaseNote, err := annotate(harness, domain.AnnotationInput{
		TargetType: "lease",
		TargetID:   leaseID,
		Category:   "action",
		Body:       "reclaimed the lease and re-observed the node",
		Author:     "oncall.bob",
		RequestKey: "incident-note-02",
	})
	if err != nil {
		return err
	}
	assessNote, err := annotate(harness, domain.AnnotationInput{
		TargetType: "assessment",
		TargetID:   assessment.ID,
		Category:   "conclusion",
		Body:       "verdict accepted after serial propagation settled",
		Author:     "oncall.alice",
		RequestKey: "incident-note-03",
	})
	if err != nil {
		return err
	}
	if leaseNote.Sequence != 2 || assessNote.Sequence != 3 {
		return ensure(false, "appends did not receive a monotonic sequence")
	}
	if leaseNote.PlanID != plan.ID || assessNote.PlanID != plan.ID {
		return ensure(false, "lease and assessment annotations did not derive the plan reference")
	}

	replay, err := annotate(harness, domain.AnnotationInput{
		TargetType: "plan",
		TargetID:   plan.ID,
		Category:   "observation",
		Body:       "edge resolvers reported stale serial during the rollout",
		Author:     "oncall.alice",
		RequestKey: "incident-note-01",
	})
	if err != nil {
		return err
	}
	if replay.ID != planNote.ID || replay.Sequence != planNote.Sequence {
		return ensure(false, "annotation replay did not return the original entry")
	}
	if page, err := planTimeline(harness, plan.ID, ""); err != nil || len(page.Items) != 3 {
		return ensure(false, "replay grew the timeline")
	}
	conflict := harness.call(http.MethodPut, "/v1/annotations", domain.AnnotationInput{
		TargetType: "plan",
		TargetID:   plan.ID,
		Category:   "observation",
		Body:       "rewritten body under the same request key",
		Author:     "oncall.alice",
		RequestKey: "incident-note-01",
	}, nil)
	if err := expectFailure(conflict, http.StatusConflict, string(domain.CodeIdempotencyConflict)); err != nil {
		return err
	}
	missing := harness.call(http.MethodPut, "/v1/annotations", domain.AnnotationInput{
		TargetType: "lease",
		TargetID:   "lse_missing",
		Category:   "observation",
		Body:       "target does not exist",
		Author:     "oncall.alice",
		RequestKey: "incident-note-04",
	}, nil)
	if err := expectFailure(missing, http.StatusNotFound, string(domain.CodeNotFound)); err != nil {
		return err
	}
	invalid := harness.call(http.MethodPut, "/v1/annotations", domain.AnnotationInput{
		TargetType: "plan",
		TargetID:   plan.ID,
		Category:   "note",
		Body:       "unsupported category",
		Author:     "oncall.alice",
		RequestKey: "incident-note-05",
	}, nil)
	if err := expectFailure(invalid, http.StatusBadRequest, string(domain.CodeValidationFailed)); err != nil {
		return err
	}

	timeline, err := planTimeline(harness, plan.ID, "")
	if err != nil {
		return err
	}
	if err := expectSequences(timeline.Items, 1, 3); err != nil {
		return err
	}
	actions, err := planTimeline(harness, plan.ID, "?category=action")
	if err != nil {
		return err
	}
	if len(actions.Items) != 1 || actions.Items[0].ID != leaseNote.ID {
		return ensure(false, "category filter did not isolate the action annotation")
	}
	assessmentsOnly, err := planTimeline(harness, plan.ID, "?target_type=assessment")
	if err != nil {
		return err
	}
	if len(assessmentsOnly.Items) != 1 || assessmentsOnly.Items[0].ID != assessNote.ID {
		return ensure(false, "target type filter did not isolate the assessment annotation")
	}
	var leaseTimeline domain.AnnotationPage
	if err := harness.call(http.MethodGet, "/v1/leases/"+leaseID+"/annotations", nil, &leaseTimeline); err != nil {
		return err
	}
	if len(leaseTimeline.Items) != 1 || leaseTimeline.Items[0].ID != leaseNote.ID {
		return ensure(false, "lease timeline does not contain its annotation")
	}
	var assessmentTimeline domain.AnnotationPage
	if err := harness.call(http.MethodGet, "/v1/assessments/"+assessment.ID+"/annotations", nil, &assessmentTimeline); err != nil {
		return err
	}
	if len(assessmentTimeline.Items) != 1 || assessmentTimeline.Items[0].ID != assessNote.ID {
		return ensure(false, "assessment timeline does not contain its annotation")
	}
	var fetched domain.IncidentAnnotation
	if err := harness.call(http.MethodGet, "/v1/annotations/"+planNote.ID, nil, &fetched); err != nil {
		return err
	}
	if fetched.Body != planNote.Body || fetched.Author != planNote.Author {
		return ensure(false, "annotation lookup returned different content")
	}
	var afterAnnotations domain.RolloutPlan
	if err := harness.call(http.MethodGet, "/v1/plans/"+plan.ID, nil, &afterAnnotations); err != nil {
		return err
	}
	if afterAnnotations.Version != before.Version {
		return ensure(false, "annotations changed plan business state")
	}

	const concurrentAppends = 8
	var wait sync.WaitGroup
	failures := make(chan error, concurrentAppends)
	for index := 0; index < concurrentAppends; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := annotate(harness, domain.AnnotationInput{
				TargetType: "plan",
				TargetID:   plan.ID,
				Category:   "hypothesis",
				Body:       fmt.Sprintf("concurrent observation %d", index),
				Author:     "oncall.carol",
				RequestKey: fmt.Sprintf("incident-conc-%02d", index),
			})
			failures <- err
		}(index)
	}
	wait.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			return err
		}
	}
	timeline, err = planTimeline(harness, plan.ID, "")
	if err != nil {
		return err
	}
	if err := expectSequences(timeline.Items, 1, 3+concurrentAppends); err != nil {
		return err
	}
	paged, err := collectTimeline(harness, plan.ID, 4)
	if err != nil {
		return err
	}
	if err := expectSequences(paged, 1, 3+concurrentAppends); err != nil {
		return err
	}

	var secondAssessment domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "incident-assess-2",
	}, &secondAssessment); err != nil {
		return err
	}
	if secondAssessment.Verdict != assessment.Verdict || secondAssessment.ProbeCount != assessment.ProbeCount {
		return ensure(false, "annotations influenced the verdict")
	}

	var current domain.RolloutPlan
	if err := harness.call(http.MethodGet, "/v1/plans/"+plan.ID, nil, &current); err != nil {
		return err
	}
	var completed domain.RolloutPlan
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/complete", map[string]any{
		"expected_version": current.Version,
	}, &completed); err != nil {
		return err
	}
	if completed.State != domain.PlanCompleted {
		return ensure(false, "plan did not complete")
	}
	timeline, err = planTimeline(harness, plan.ID, "")
	if err != nil {
		return err
	}
	if err := expectSequences(timeline.Items, 1, 3+concurrentAppends); err != nil {
		return err
	}
	postCompletion, err := annotate(harness, domain.AnnotationInput{
		TargetType: "plan",
		TargetID:   plan.ID,
		Category:   "conclusion",
		Body:       "postmortem recorded after plan completion",
		Author:     "oncall.alice",
		RequestKey: "incident-note-06",
	})
	if err != nil {
		return err
	}
	if postCompletion.Sequence != 4+concurrentAppends {
		return ensure(false, "post-completion append did not extend the timeline")
	}
	var frozen domain.RolloutPlan
	if err := harness.call(http.MethodGet, "/v1/plans/"+plan.ID, nil, &frozen); err != nil {
		return err
	}
	if frozen.State != domain.PlanCompleted || frozen.Version != completed.Version {
		return ensure(false, "post-completion annotation changed plan state")
	}
	var thirdAssessment domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "incident-assess-3",
	}, &thirdAssessment); err != nil {
		return err
	}
	if thirdAssessment.Verdict != assessment.Verdict {
		return ensure(false, "annotations influenced a verdict after completion")
	}
	erase := harness.call(http.MethodDelete, "/v1/annotations/"+planNote.ID, nil, nil)
	if err := expectFailure(erase, http.StatusMethodNotAllowed, ""); err != nil {
		return err
	}

	if err := harness.restart(); err != nil {
		return err
	}
	timeline, err = planTimeline(harness, plan.ID, "")
	if err != nil {
		return err
	}
	if err := expectSequences(timeline.Items, 1, 4+concurrentAppends); err != nil {
		return err
	}
	if timeline.Items[0].ID != planNote.ID || timeline.Items[len(timeline.Items)-1].ID != postCompletion.ID {
		return ensure(false, "restart changed the timeline order")
	}
	var reopened domain.IncidentAnnotation
	if err := harness.call(http.MethodGet, "/v1/annotations/"+assessNote.ID, nil, &reopened); err != nil {
		return err
	}
	if reopened.TargetID != assessment.ID || reopened.PlanID != plan.ID {
		return ensure(false, "restart broke annotation references")
	}
	var leaseTimelineAfter domain.AnnotationPage
	if err := harness.call(http.MethodGet, "/v1/leases/"+leaseID+"/annotations", nil, &leaseTimelineAfter); err != nil {
		return err
	}
	if len(leaseTimelineAfter.Items) != 1 || leaseTimelineAfter.Items[0].ID != leaseNote.ID {
		return ensure(false, "restart lost the lease annotation reference")
	}
	return nil
}

func annotate(harness *harness, input domain.AnnotationInput) (domain.IncidentAnnotation, error) {
	var annotation domain.IncidentAnnotation
	err := harness.call(http.MethodPut, "/v1/annotations", input, &annotation)
	return annotation, err
}

func planTimeline(harness *harness, planID string, query string) (domain.AnnotationPage, error) {
	var page domain.AnnotationPage
	err := harness.call(http.MethodGet, "/v1/plans/"+planID+"/annotations"+query, nil, &page)
	return page, err
}

func collectTimeline(harness *harness, planID string, limit int) ([]domain.IncidentAnnotation, error) {
	items := make([]domain.IncidentAnnotation, 0)
	cursor := ""
	for {
		query := fmt.Sprintf("?limit=%d", limit)
		if cursor != "" {
			query += "&cursor=" + cursor
		}
		page, err := planTimeline(harness, planID, query)
		if err != nil {
			return nil, err
		}
		items = append(items, page.Items...)
		if page.Meta.NextCursor == "" {
			return items, nil
		}
		cursor = page.Meta.NextCursor
	}
}

func expectSequences(items []domain.IncidentAnnotation, first uint64, count int) error {
	if len(items) != count {
		return ensure(false, "timeline length does not match the appended entries")
	}
	seen := make(map[uint64]bool, count)
	for index, item := range items {
		expected := first + uint64(index)
		if item.Sequence != expected {
			return ensure(false, "timeline order is not the append sequence")
		}
		if seen[item.Sequence] {
			return ensure(false, "timeline contains a duplicate sequence")
		}
		seen[item.Sequence] = true
	}
	return nil
}
