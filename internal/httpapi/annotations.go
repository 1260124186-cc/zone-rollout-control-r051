package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"solo-0014-zone-rollout-control/internal/domain"
)

func (s *Server) appendAnnotation(w http.ResponseWriter, r *http.Request) {
	var input domain.AnnotationInput
	if err := decode(w, r, &input); err != nil {
		sendError(w, r, err)
		return
	}
	result, err := s.annotations.Append(r.Context(), input)
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusCreated, result)
}

func (s *Server) getAnnotation(w http.ResponseWriter, r *http.Request) {
	result, err := s.annotations.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, result)
}

func (s *Server) listPlanAnnotations(w http.ResponseWriter, r *http.Request) {
	limit, ok := annotationLimit(w, r)
	if !ok {
		return
	}
	category := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("category")))
	if category != "" && !domain.ValidAnnotationCategory(category) {
		sendError(w, r, domain.Validation("annotation category is not supported", map[string]any{"category": category}))
		return
	}
	targetType := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("target_type")))
	if targetType != "" && !domain.ValidAnnotationTargetType(targetType) {
		sendError(w, r, domain.Validation("annotation target type is not supported", map[string]any{"target_type": targetType}))
		return
	}
	page, err := s.annotations.ListForPlan(
		r.Context(),
		r.PathValue("id"),
		domain.AnnotationCategory(category),
		domain.AnnotationTargetType(targetType),
		limit,
		r.URL.Query().Get("cursor"),
	)
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, page)
}

func (s *Server) listLeaseAnnotations(w http.ResponseWriter, r *http.Request) {
	s.listTargetAnnotations(w, r, domain.AnnotationTargetLease)
}

func (s *Server) listAssessmentAnnotations(w http.ResponseWriter, r *http.Request) {
	s.listTargetAnnotations(w, r, domain.AnnotationTargetAssessment)
}

func (s *Server) listTargetAnnotations(
	w http.ResponseWriter,
	r *http.Request,
	targetType domain.AnnotationTargetType,
) {
	limit, ok := annotationLimit(w, r)
	if !ok {
		return
	}
	page, err := s.annotations.ListForTarget(
		r.Context(),
		targetType,
		r.PathValue("id"),
		limit,
		r.URL.Query().Get("cursor"),
	)
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, page)
}

func annotationLimit(w http.ResponseWriter, r *http.Request) (int, bool) {
	limit := 50
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return limit, true
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		sendError(w, r, domain.Validation("limit must be an integer", map[string]any{"limit": raw}))
		return 0, false
	}
	return parsed, true
}
