package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"solo-0014-zone-rollout-control/internal/annotation"
	"solo-0014-zone-rollout-control/internal/domain"
)

const defaultAnnotationLimit = 50

func (s *Server) appendAnnotation(w http.ResponseWriter, r *http.Request) {
	var input domain.AnnotationInput
	if err := decode(w, r, &input); err != nil {
		sendError(w, r, err)
		return
	}
	origin := annotation.Origin{
		Source:    "http-api",
		RequestID: requestID(r.Context()),
	}
	result, err := s.annotations.Append(r.Context(), input, origin)
	if err != nil {
		sendError(w, r, err)
		return
	}
	status := http.StatusCreated
	if !result.Created {
		status = http.StatusOK
	}
	sendData(w, r, status, result.Annotation)
}

func (s *Server) getAnnotation(w http.ResponseWriter, r *http.Request) {
	result, err := s.annotations.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, result)
}

func (s *Server) listAnnotations(w http.ResponseWriter, r *http.Request) {
	limit, err := parseLimit(r, defaultAnnotationLimit)
	if err != nil {
		sendError(w, r, err)
		return
	}
	page, err := s.annotations.List(
		r.Context(),
		"",
		limit,
		r.URL.Query().Get("cursor"),
	)
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, page)
}

func (s *Server) listPlanAnnotations(w http.ResponseWriter, r *http.Request) {
	limit, err := parseLimit(r, defaultAnnotationLimit)
	if err != nil {
		sendError(w, r, err)
		return
	}
	page, err := s.annotations.List(
		r.Context(),
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
	items, err := s.annotations.ListForTarget(r.Context(), targetType, r.PathValue("id"))
	if err != nil {
		sendError(w, r, err)
		return
	}
	sendData(w, r, http.StatusOK, map[string]any{
		"target_type": targetType,
		"target_id":   r.PathValue("id"),
		"items":       items,
	})
}

func parseLimit(r *http.Request, fallback int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return fallback, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil {
		return 0, domain.Validation("limit must be an integer", map[string]any{"limit": raw})
	}
	return limit, nil
}
