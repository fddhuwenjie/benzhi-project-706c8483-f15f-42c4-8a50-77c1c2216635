package materialtrackingcachealias_test

import (
	"errors"
	"testing"

	cases "museumenv/internal/case"
	"museumenv/internal/store"
)

type materialRepository struct {
	incidents []store.EnvironmentIncident
}

func (r *materialRepository) Create(store.Mutation, *store.EnvironmentIncident) (*store.EnvironmentIncident, bool, error) {
	return nil, false, errors.New("not implemented")
}

func (r *materialRepository) Update(store.Mutation, store.MutateFunc) (*store.EnvironmentIncident, bool, error) {
	return nil, false, errors.New("not implemented")
}

func (r *materialRepository) Get(string) (*store.EnvironmentIncident, error) {
	return nil, store.ErrNotFound
}

func (r *materialRepository) List() ([]store.EnvironmentIncident, error) {
	return r.incidents, nil
}

func (r *materialRepository) Query(store.IncidentQuery) (store.IncidentPage, error) {
	return store.IncidentPage{}, errors.New("not implemented")
}

func (r *materialRepository) Timeline(string) ([]store.AuditEvent, error) {
	return nil, errors.New("not implemented")
}

func (r *materialRepository) Evidence(string) (store.EvidenceSummary, error) {
	return store.EvidenceSummary{}, errors.New("not implemented")
}

func TestMaterialTrackingFilterDoesNotPoisonCache(t *testing.T) {
	repository := &materialRepository{incidents: []store.EnvironmentIncident{
		{
			IncidentID: "inc-a",
			Revision:   7,
			Executions: []store.Execution{{
				ExecutionID: "exec-a",
				OperatorID:  "operator-a",
				PlanVersion: 3,
				Materials:   []store.MaterialUsage{{Name: "吸湿材料", BatchNumber: "batch-a", Quantity: 1.0}},
			}},
		},
		{
			IncidentID: "inc-b",
			Revision:   4,
			Executions: []store.Execution{{
				ExecutionID: "exec-b",
				OperatorID:  "operator-b",
				PlanVersion: 5,
				Materials:   []store.MaterialUsage{{Name: "缓冲材料", BatchNumber: "batch-b", Quantity: 2.0}},
			}},
		},
	}}
	service := cases.NewService(repository)

	initial, err := service.MaterialBatchTracking("")
	if err != nil || len(initial) != 2 {
		t.Fatalf("初次全量查询失败: count=%d err=%v", len(initial), err)
	}
	for i := range initial {
		if initial[i].BatchNumber == "batch-b" {
			initial[i].Operators[0] = "tampered-operator"
			initial[i].QuantityValues[0] = 99.0
			initial[i].ExecutionIDs[0] = "tampered-execution"
			initial[i].PlanVersions[0] = 99
		}
	}

	after, err := service.MaterialBatchTracking("batch-b")
	if err != nil || len(after) != 1 {
		t.Fatalf("缓存复用查询失败: count=%d err=%v", len(after), err)
	}
	got := after[0]
	if got.Operators[0] != "operator-b" || got.QuantityValues[0] != 2.0 || got.ExecutionIDs[0] != "exec-b" || got.PlanVersions[0] != 5 {
		t.Fatalf("调用方修改返回值污染了缓存，后续汇总为 %#v", got)
	}
}
