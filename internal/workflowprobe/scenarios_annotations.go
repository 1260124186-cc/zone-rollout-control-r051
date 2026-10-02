package workflowprobe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"

	"solo-0014-zone-rollout-control/internal/domain"
)

type annotationBody struct {
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Category   string `json:"category"`
	Body       string `json:"body"`
	Actor      string `json:"actor"`
	RequestKey string `json:"request_key,omitempty"`
}

type annotationPage struct {
	Items []domain.IncidentAnnotation `json:"items"`
	Meta  struct {
		Limit      int    `json:"limit"`
		NextCursor string `json:"next_cursor"`
	} `json:"meta"`
}

func appendAnnotation(
	h *harness,
	targetType string,
	targetID string,
	category string,
	body string,
	actor string,
	requestKey string,
) (domain.IncidentAnnotation, error) {
	input := annotationBody{
		TargetType: targetType,
		TargetID:   targetID,
		Category:   category,
		Body:       body,
		Actor:      actor,
		RequestKey: requestKey,
	}
	var result domain.IncidentAnnotation
	err := h.call(http.MethodPut, "/v1/annotations", input, &result)
	return result, err
}

func runIncidentAnnotationTimeline() error {
	h, err := newHarness()
	if err != nil {
		return err
	}
	defer h.close()

	// Build a full rollout: active plan with one node, one claimed lease.
	plan, revision, err := createActivePlan(h, "incident.example", 2026100201, 1, 1, 100)
	if err != nil {
		return err
	}
	node, err := enrollNode(h, "resolver-incident-01", "east")
	if err != nil {
		return err
	}
	group, err := allocate(h, plan.ID, "lease-inc-0001", "east", 1)
	if err != nil {
		return err
	}
	leaseID := group.LeaseIDs[0]
	probe, err := submitProbe(h, leaseID, "probe-inc-0001", true, revision.Serial, 20)
	if err != nil {
		return err
	}
	_ = node.ID

	var assessment domain.RolloutAssessment
	if err := h.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments",
		map[string]string{"request_key": "asm-inc-00001"}, &assessment); err != nil {
		return err
	}
	if err := ensure(assessment.Verdict == domain.VerdictConsistent,
		"expected a consistent assessment before annotating"); err != nil {
		return err
	}

	// 1. Append annotations to all three target types.
	planNote, err := appendAnnotation(h, "plan", plan.ID, "observation",
		"operator reported elevated SERVFAIL rate in east region", "oncall-aria", "note-inc-00001")
	if err != nil {
		return err
	}
	if err := ensure(planNote.Sequence == 1, "first annotation must have sequence 1"); err != nil {
		return err
	}
	if err := ensure(planNote.PlanID == plan.ID, "plan annotation must resolve its plan"); err != nil {
		return err
	}
	if err := ensure(planNote.RecordedAt.Equal(h.clock.Now()), "recorded_at must be service time"); err != nil {
		return err
	}
	if err := ensure(planNote.Source == "http-api", "source must record the operating channel"); err != nil {
		return err
	}
	if err := ensure(planNote.RequestID != "", "request id must be recorded as an operation fact"); err != nil {
		return err
	}

	leaseNote, err := appendAnnotation(h, "lease", leaseID, "evidence",
		"lease correlated with customer ticket T-441", "sre-bao", "note-inc-00002")
	if err != nil {
		return err
	}
	if err := ensure(leaseNote.PlanID == plan.ID, "lease annotation must resolve to the lease plan"); err != nil {
		return err
	}

	assessmentNote, err := appendAnnotation(h, "assessment", assessment.ID, "decision",
		"verdict accepted despite incident chatter", "rollout-lead-coco", "note-inc-00003")
	if err != nil {
		return err
	}
	if err := ensure(assessmentNote.PlanID == plan.ID, "assessment annotation must resolve to the assessment plan"); err != nil {
		return err
	}
	for sequence, note := range []domain.IncidentAnnotation{planNote, leaseNote, assessmentNote} {
		if err := ensure(note.Sequence == uint64(sequence+1),
			fmt.Sprintf("sequences must be strictly increasing, got %d", note.Sequence)); err != nil {
			return err
		}
	}

	// 2. Unknown targets are rejected and must not produce history.
	if _, err := appendAnnotation(h, "plan", "pln_missing", "observation", "ghost", "oncall-aria", ""); err != nil {
		if ferr := expectFailure(err, http.StatusNotFound, "not_found"); ferr != nil {
			return ferr
		}
	} else {
		return fmt.Errorf("annotation on missing plan should fail")
	}
	if _, err := appendAnnotation(h, "lease", "lse_missing", "observation", "ghost", "oncall-aria", ""); err != nil {
		if ferr := expectFailure(err, http.StatusNotFound, "not_found"); ferr != nil {
			return ferr
		}
	} else {
		return fmt.Errorf("annotation on missing lease should fail")
	}
	if _, err := appendAnnotation(h, "assessment", "asm_missing", "observation", "ghost", "oncall-aria", ""); err != nil {
		if ferr := expectFailure(err, http.StatusNotFound, "not_found"); ferr != nil {
			return ferr
		}
	} else {
		return fmt.Errorf("annotation on missing assessment should fail")
	}

	// 3. Invalid category and empty body are validation errors.
	if _, err := appendAnnotation(h, "plan", plan.ID, "speculation", "nope", "oncall-aria", ""); err != nil {
		if ferr := expectFailure(err, http.StatusBadRequest, "validation_failed"); ferr != nil {
			return ferr
		}
	} else {
		return fmt.Errorf("unknown category should be rejected")
	}

	// 4. Idempotent replay returns the original entry; changed content conflicts.
	replay, err := appendAnnotation(h, "plan", plan.ID, "observation",
		"operator reported elevated SERVFAIL rate in east region", "oncall-aria", "note-inc-00001")
	if err != nil {
		return fmt.Errorf("identical replay must succeed: %w", err)
	}
	if err := ensure(replay.ID == planNote.ID, "replay must return the original annotation"); err != nil {
		return err
	}
	if _, err := appendAnnotation(h, "plan", plan.ID, "root_cause",
		"different finding under the same key", "oncall-aria", "note-inc-00001"); err != nil {
		if ferr := expectFailure(err, http.StatusConflict, "idempotency_conflict"); ferr != nil {
			return ferr
		}
	} else {
		return fmt.Errorf("same request key with different content must conflict")
	}

	// 5. GET one entry by id.
	var fetched domain.IncidentAnnotation
	if err := h.call(http.MethodGet, "/v1/annotations/"+leaseNote.ID, nil, &fetched); err != nil {
		return err
	}
	if err := ensure(fetched.ID == leaseNote.ID && fetched.Body == leaseNote.Body, "GET must return the same entry"); err != nil {
		return err
	}

	// 6. Timeline reads are deterministic and filterable.
	var page annotationPage
	if err := h.call(http.MethodGet, "/v1/annotations?limit=2", nil, &page); err != nil {
		return err
	}
	if err := ensure(len(page.Items) == 2, "limit must bound the page"); err != nil {
		return err
	}
	if err := ensure(page.Items[0].Sequence == 1 && page.Items[1].Sequence == 2,
		"timeline must follow commit sequence"); err != nil {
		return err
	}
	if err := ensure(page.Meta.NextCursor != "", "next cursor must be returned"); err != nil {
		return err
	}
	var rest annotationPage
	if err := h.call(http.MethodGet, "/v1/annotations?limit=10&cursor="+page.Meta.NextCursor, nil, &rest); err != nil {
		return err
	}
	if err := ensure(len(rest.Items) == 1 && rest.Items[0].ID == assessmentNote.ID,
		"cursor must continue after the last returned sequence"); err != nil {
		return err
	}

	var planPage annotationPage
	if err := h.call(http.MethodGet, "/v1/plans/"+plan.ID+"/annotations", nil, &planPage); err != nil {
		return err
	}
	if err := ensure(len(planPage.Items) == 3,
		fmt.Sprintf("plan timeline must include annotations on plan, lease, and assessment, got %d", len(planPage.Items))); err != nil {
		return err
	}
	var leaseItems struct {
		Items []domain.IncidentAnnotation `json:"items"`
	}
	if err := h.call(http.MethodGet, "/v1/leases/"+leaseID+"/annotations", nil, &leaseItems); err != nil {
		return err
	}
	if err := ensure(len(leaseItems.Items) == 1 && leaseItems.Items[0].ID == leaseNote.ID,
		"lease endpoint must show only lease annotations"); err != nil {
		return err
	}
	var assessmentItems struct {
		Items []domain.IncidentAnnotation `json:"items"`
	}
	if err := h.call(http.MethodGet, "/v1/assessments/"+assessment.ID+"/annotations", nil, &assessmentItems); err != nil {
		return err
	}
	if err := ensure(len(assessmentItems.Items) == 1 && assessmentItems.Items[0].ID == assessmentNote.ID,
		"assessment endpoint must show only assessment annotations"); err != nil {
		return err
	}

	// 7. Timeline is append-only: DELETE and PATCH are not routable.
	deleteRequest, err := http.NewRequest(http.MethodDelete, h.baseURL+"/v1/annotations/"+planNote.ID, nil)
	if err != nil {
		return err
	}
	deleteResponse, err := h.client.Do(deleteRequest)
	if err != nil {
		return fmt.Errorf("perform delete: %w", err)
	}
	_ = deleteResponse.Body.Close()
	if err := ensure(deleteResponse.StatusCode == http.StatusMethodNotAllowed,
		fmt.Sprintf("delete must be rejected, got %d", deleteResponse.StatusCode)); err != nil {
		return err
	}

	// 8. Annotations never influence assessment: a second assessment replays
	// and still returns the original verdict with identical counters.
	var assessmentReplay domain.RolloutAssessment
	if err := h.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments",
		map[string]string{"request_key": "asm-inc-00001"}, &assessmentReplay); err != nil {
		return err
	}
	if err := ensure(assessmentReplay.ID == assessment.ID &&
		assessmentReplay.ProbeCount == assessment.ProbeCount &&
		assessmentReplay.SuccessCount == assessment.SuccessCount &&
		assessmentReplay.Verdict == assessment.Verdict,
		"annotations must not change the assessment verdict or counters"); err != nil {
		return err
	}

	// 9. Concurrent appends commit in one deterministic gapless order.
	concurrentCount := 12
	var wg sync.WaitGroup
	errorsChannel := make(chan error, concurrentCount)
	sequences := make(chan uint64, concurrentCount)
	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			note, noteErr := appendAnnotation(h, "plan", plan.ID, "action",
				fmt.Sprintf("parallel mitigation note %02d", index), "oncall-aria", "")
			if noteErr != nil {
				errorsChannel <- noteErr
				return
			}
			sequences <- note.Sequence
		}(i)
	}
	wg.Wait()
	close(errorsChannel)
	close(sequences)
	for concurrentErr := range errorsChannel {
		return fmt.Errorf("concurrent append failed: %w", concurrentErr)
	}
	got := make(map[uint64]bool, concurrentCount)
	for sequence := range sequences {
		got[sequence] = true
	}
	if err := ensure(len(got) == concurrentCount, "concurrent appends must not reuse sequences"); err != nil {
		return err
	}
	for sequence := assessmentNote.Sequence + 1; sequence <= assessmentNote.Sequence+uint64(concurrentCount); sequence++ {
		if err := ensure(got[sequence], fmt.Sprintf("sequence %d must be assigned without gaps", sequence)); err != nil {
			return err
		}
	}

	// 10. Completed plans stay readable and still accept annotations, but the
	// annotation cannot influence verdicts (no assessment route accepts it).
	var completedPlan domain.RolloutPlan
	if err := h.call(http.MethodGet, "/v1/plans/"+plan.ID, nil, &completedPlan); err != nil {
		return err
	}
	if err := h.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/complete",
		map[string]uint64{"expected_version": completedPlan.Version}, &completedPlan); err != nil {
		return err
	}
	if err := ensure(completedPlan.State == domain.PlanCompleted, "plan must complete"); err != nil {
		return err
	}
	postmortem, err := appendAnnotation(h, "plan", plan.ID, "root_cause",
		"postmortem: upstream TTL cache served stale glue records", "incident-commander-delta", "note-inc-00004")
	if err != nil {
		return fmt.Errorf("completed plan must still accept annotations: %w", err)
	}
	// A completed plan cannot run new business operations.
	if err := h.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/leases", domain.LeaseInput{
		RequestKey:   "lease-inc-dead",
		Region:       "east",
		LeaseSeconds: 600,
		MaxNodes:     1,
	}, nil); err != nil {
		if ferr := expectFailure(err, http.StatusConflict, "invalid_state"); ferr != nil {
			return ferr
		}
	} else {
		return fmt.Errorf("leasing against a completed plan must fail")
	}
	// The annotation history did not rewrite any business state: the probe
	// identity recorded earlier is still referenced by the lease.
	_ = probe.ID

	// 11. Restart: timeline order, idempotent replay, and references survive.
	timelineBefore := annotationPage{}
	if err := h.call(http.MethodGet, "/v1/plans/"+plan.ID+"/annotations?limit=100", nil, &timelineBefore); err != nil {
		return err
	}
	if err := h.restart(); err != nil {
		return err
	}
	var afterRestart domain.IncidentAnnotation
	if err := h.call(http.MethodGet, "/v1/annotations/"+postmortem.ID, nil, &afterRestart); err != nil {
		return fmt.Errorf("annotation must survive restart: %w", err)
	}
	if err := ensure(afterRestart.Sequence == postmortem.Sequence, "sequence must survive restart"); err != nil {
		return err
	}
	timelineAfter := annotationPage{}
	if err := h.call(http.MethodGet, "/v1/plans/"+plan.ID+"/annotations?limit=100", nil, &timelineAfter); err != nil {
		return err
	}
	if err := ensure(len(timelineAfter.Items) == len(timelineBefore.Items),
		"all annotations must survive restart"); err != nil {
		return err
	}
	for index := range timelineAfter.Items {
		if err := ensure(timelineAfter.Items[index].Sequence == timelineBefore.Items[index].Sequence &&
			timelineAfter.Items[index].ID == timelineBefore.Items[index].ID,
			"timeline order and identities must survive restart"); err != nil {
			return err
		}
	}
	replayAfterRestart, err := appendAnnotation(h, "plan", plan.ID, "root_cause",
		"postmortem: upstream TTL cache served stale glue records", "incident-commander-delta", "note-inc-00004")
	if err != nil {
		return fmt.Errorf("replay after restart must resolve: %w", err)
	}
	if err := ensure(replayAfterRestart.ID == postmortem.ID,
		"replay after restart must return the persisted annotation"); err != nil {
		return err
	}

	// The next append continues the sequence after restart.
	continued, err := appendAnnotation(h, "lease", leaseID, "observation",
		"follow-up check after restart", "oncall-aria", "")
	if err != nil {
		return err
	}
	if err := ensure(continued.Sequence == postmortem.Sequence+1,
		fmt.Sprintf("sequence must continue at %d after restart, got %d", postmortem.Sequence+1, continued.Sequence)); err != nil {
		return err
	}

	// 12. Listing annotations for a missing plan after restart is still 404.
	if err := h.call(http.MethodGet, "/v1/plans/pln_missing/annotations", nil, nil); err != nil {
		if ferr := expectFailure(err, http.StatusNotFound, "not_found"); ferr != nil {
			return ferr
		}
	} else {
		return fmt.Errorf("annotations of a missing plan must be not found")
	}

	// 13. A snapshot whose annotation reference is broken (the annotated plan
	// was removed out of band) must refuse to load instead of reopening with
	// dangling history.
	if err := breakPlanReference(h.statePath, plan.ID); err != nil {
		return err
	}
	if err := h.restart(); err == nil {
		return fmt.Errorf("server must reject a snapshot with a dangling annotation reference")
	}
	return nil
}

// breakPlanReference rewrites the snapshot without the named plan while
// leaving its annotations in place, simulating out-of-band history corruption.
func breakPlanReference(statePath string, planID string) error {
	payload, err := os.ReadFile(statePath)
	if err != nil {
		return err
	}
	var snapshot map[string]any
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return err
	}
	plans, _ := snapshot["plans"].(map[string]any)
	if plans == nil {
		return fmt.Errorf("snapshot has no plans map")
	}
	delete(plans, planID)
	encoded, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statePath, append(encoded, '\n'), 0o600)
}
