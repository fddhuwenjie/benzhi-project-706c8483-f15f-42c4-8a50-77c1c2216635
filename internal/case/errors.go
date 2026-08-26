package cases

import (
	"errors"
	"fmt"
	"strings"

	"museumenv/internal/store"
)

type Error struct {
	Code    string
	Message string
	Cause   error
	Details map[string]any
}

func (e *Error) Error() string { return e.Message }
func (e *Error) Unwrap() error { return e.Cause }

func invalid(message string) error      { return &Error{Code: "INVALID_ARGUMENT", Message: message} }
func precondition(message string) error { return &Error{Code: "PRECONDITION_FAILED", Message: message} }
func invalidField(field, message string) error {
	return &Error{Code: "INVALID_ARGUMENT", Message: message, Details: map[string]any{"field": field}}
}

func translateStoreError(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return &Error{Code: "INCIDENT_NOT_FOUND", Message: "未找到指定的异常事件", Cause: err}
	case errors.Is(err, store.ErrRevisionConflict):
		return &Error{Code: "REVISION_CONFLICT", Message: "数据版本已变化，请重新获取异常详情", Cause: err}
	case errors.Is(err, store.ErrAlreadyExists):
		return &Error{Code: "INCIDENT_ALREADY_EXISTS", Message: "异常编号已存在", Cause: err}
	case errors.Is(err, store.ErrSealed):
		return &Error{Code: "SEALED", Message: "事件已经封存，不能再写入业务数据", Cause: err}
	default:
		if strings.Contains(err.Error(), "evidence integrity") {
			return &Error{Code: "EVIDENCE_INTEGRITY_FAILED", Message: "封存证据完整性校验失败：" + strings.TrimPrefix(err.Error(), "evidence integrity: "), Cause: err}
		}
		var active *store.ActiveIncidentError
		if errors.As(err, &active) {
			return &Error{Code: "ACTIVE_INCIDENT_CONFLICT", Message: "同一展柜与传感器已有未封存事件，请转入原事件处置", Cause: err, Details: map[string]any{"incident_id": active.IncidentID, "case_number": active.CaseNumber, "status": active.Status, "revision": active.Revision}}
		}
		var domain *Error
		if errors.As(err, &domain) {
			return err
		}
		return &Error{Code: "INTERNAL_ERROR", Message: "保存异常事件失败", Cause: fmt.Errorf("store: %w", err)}
	}
}
