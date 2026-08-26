package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	cases "museumenv/internal/case"
	"museumenv/internal/httpapi"
	"museumenv/internal/store"
)

type config struct {
	address   string
	dataFile  string
	selfCheck bool
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Printf("服务退出：%v", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	configuration, err := parseConfig(arguments)
	if err != nil {
		return err
	}
	if configuration.selfCheck {
		return runSelfCheck(configuration.address)
	}
	repository, err := store.Open(configuration.dataFile)
	if err != nil {
		return fmt.Errorf("打开持久化存储: %w", err)
	}
	handler := httpapi.New(cases.NewService(repository)).Handler()
	listener, err := net.Listen("tcp", configuration.address)
	if err != nil {
		return fmt.Errorf("监听 %s: %w", configuration.address, err)
	}
	server := configuredServer(handler)
	log.Printf("展柜微环境异常复原台已启动 addr=%s data=%s", listener.Addr(), configuration.dataFile)
	errorChannel := make(chan error, 1)
	go func() { errorChannel <- server.Serve(listener) }()
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case serveErr := <-errorChannel:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("HTTP 服务异常: %w", serveErr)
		}
		return nil
	case <-signalContext.Done():
		log.Printf("收到终止信号，开始优雅关闭")
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("优雅关闭失败: %w", err)
	}
	serveErr := <-errorChannel
	if !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}

func parseConfig(arguments []string) (config, error) {
	defaultAddress := "127.0.0.1:19081"
	if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return config{}, fmt.Errorf("PORT 必须是 1 至 65535 的端口号")
		}
		defaultAddress = net.JoinHostPort("127.0.0.1", port)
	}
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	address := flags.String("addr", defaultAddress, "HTTP 回环监听地址")
	dataFile := flags.String("data", "var/microenvironment.json", "本地 JSON 数据文件")
	selfCheck := flags.Bool("self-check", false, "运行真实 HTTP 全流程自检后退出")
	if err := flags.Parse(arguments); err != nil {
		return config{}, fmt.Errorf("解析启动参数: %w", err)
	}
	if flags.NArg() != 0 {
		return config{}, fmt.Errorf("存在无法识别的位置参数")
	}
	if err := validateLoopbackAddress(*address); err != nil {
		return config{}, err
	}
	if strings.TrimSpace(*dataFile) == "" {
		return config{}, fmt.Errorf("-data 不能为空")
	}
	return config{address: *address, dataFile: *dataFile, selfCheck: *selfCheck}, nil
}

func validateLoopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("-addr 必须采用 host:port 格式: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("-addr 仅允许明确的回环 IP 地址")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("-addr 端口必须在 1 至 65535 之间")
	}
	return nil
}

func configuredServer(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
}

type selfCheckClient struct {
	baseURL      string
	client       *http.Client
	incidentID   string
	revision     int64
	requestCount int
}

type wireEnvelope struct {
	Data json.RawMessage `json:"data"`
}

func runSelfCheck(address string) error {
	temporaryDirectory, err := os.MkdirTemp("", "microenv-self-check-")
	if err != nil {
		return fmt.Errorf("创建自检临时目录: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)
	repository, err := store.Open(filepath.Join(temporaryDirectory, "data.json"))
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("自检监听 %s: %w", address, err)
	}
	server := configuredServer(httpapi.New(cases.NewService(repository)).Handler())
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	client := &selfCheckClient{baseURL: "http://" + listener.Addr().String(), client: &http.Client{Timeout: 5 * time.Second}}
	flowErr := client.executeFlow()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownContext)
	serveErr := <-done
	if flowErr != nil {
		return flowErr
	}
	if shutdownErr != nil {
		return fmt.Errorf("关闭自检 HTTP 服务: %w", shutdownErr)
	}
	if !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("自检 HTTP 服务: %w", serveErr)
	}
	fmt.Printf("自检通过：addr=%s incident_id=%s status=sealed http_requests=%d evidence_chain=valid\n", address, client.incidentID, client.requestCount)
	return nil
}

func (c *selfCheckClient) executeFlow() error {
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := c.request(http.MethodGet, "/healthz", nil, http.StatusOK); err != nil {
		return err
	}
	create := map[string]any{"meta": map[string]any{"request_id": "self-create", "actor_id": "operator-01", "actor_role": "preventive_conservator"}, "display_case_id": "case-A01", "artifact_id": "artifact-001", "sensor_id": "sensor-TH-01", "sensitivity": "high", "abnormal_since": now.Add(-6 * time.Hour), "temperature_celsius": 27.0, "relative_humidity_percent": 68.0, "target_temperature_range": map[string]any{"min": 18.0, "max": 22.0}, "target_humidity_range": map[string]any{"min": 45.0, "max": 55.0}, "sensor_status": "ok"}
	if err := c.command("/v1/environment-incidents", create, http.StatusCreated); err != nil {
		return err
	}
	inspection := map[string]any{"meta": c.meta("self-inspection", "inspector-01", "preventive_conservator"), "finding": "柜门密封条局部松脱，柜内湿度持续偏高", "cause_hypotheses": []string{"密封条失效", "调湿材料饱和"}, "isolation_measure": "暂停开放并设置围挡，限制柜门操作", "independent_reading": c.reading(now.Add(-5*time.Hour), 26.5, 67.0, "FIELD-METER-CAL-01"), "alternative_monitoring": "使用校准便携仪表每十五分钟复测", "alternative_review_at": now.Add(24 * time.Hour)}
	if err := c.command(c.path("/inspection"), inspection, http.StatusOK); err != nil {
		return err
	}
	plan := map[string]any{"meta": c.meta("self-plan", "planner-01", "preventive_conservator"), "steps": []string{"更换密封条", "更换调湿材料", "校准传感器并复测"}, "target_temperature_range": map[string]any{"min": 18.0, "max": 22.0}, "target_humidity_range": map[string]any{"min": 45.0, "max": 55.0}, "isolation_required": true}
	if err := c.command(c.path("/plans"), plan, http.StatusOK); err != nil {
		return err
	}
	review := map[string]any{"meta": c.meta("self-review", "engineer-01", "conservation_engineer"), "decision": "approve", "note": "边界与步骤符合保护要求"}
	if err := c.command(c.path("/plan-review"), review, http.StatusOK); err != nil {
		return err
	}
	execution := map[string]any{"meta": c.meta("self-execution", "operator-02", "preventive_conservator"), "executed_at": now.Add(-2 * time.Hour), "notes": "按审核方案执行完毕", "step_results": []map[string]any{{"step_number": 1, "result": "completed"}, {"step_number": 2, "result": "completed"}, {"step_number": 3, "result": "completed"}}, "materials": []map[string]any{{"name": "硅胶调湿材料", "batch_number": "SG-20260826", "quantity": "2 kg", "expires_at": now.AddDate(1, 0, 0)}}, "calibration_before": c.reading(now.Add(-130*time.Minute), 22.8, 57.0, "CAL-REF-01"), "calibration_after": c.reading(now.Add(-120*time.Minute), 21.0, 52.0, "CAL-REF-01")}
	if err := c.command(c.path("/execution"), execution, http.StatusOK); err != nil {
		return err
	}
	observations := map[string]any{"meta": c.meta("self-observe", "operator-02", "preventive_conservator"), "readings": []map[string]any{c.reading(now.Add(-90*time.Minute), 20.8, 51.5, ""), c.reading(now.Add(-75*time.Minute), 20.8, 51.3, ""), c.reading(now.Add(-60*time.Minute), 20.7, 51.0, ""), c.reading(now.Add(-45*time.Minute), 20.7, 50.9, ""), c.reading(now.Add(-30*time.Minute), 20.7, 50.8, "")}}
	if err := c.command(c.path("/observations"), observations, http.StatusOK); err != nil {
		return err
	}
	verification := map[string]any{"meta": c.meta("self-verify", "verifier-01", "preventive_conservator"), "minimum_stable_minutes": 60, "minimum_readings": 5}
	if err := c.command(c.path("/verification"), verification, http.StatusOK); err != nil {
		return err
	}
	signature := map[string]any{"meta": c.meta("self-sign", "supervisor-01", "duty_supervisor"), "decision": "reopen", "note": "恢复读数与操作证据完整，同意重新开放"}
	if err := c.command(c.path("/reopen-signature"), signature, http.StatusOK); err != nil {
		return err
	}
	raw, err := c.request(http.MethodGet, c.path("/evidence"), nil, http.StatusOK)
	if err != nil {
		return err
	}
	var summary store.EvidenceSummary
	if err := decodeData(raw, &summary); err != nil {
		return err
	}
	if !summary.Sealed || summary.EventCount != 8 || summary.LatestDigest == "" {
		return fmt.Errorf("封存证据摘要不符合预期: %+v", summary)
	}
	if _, err := c.request(http.MethodGet, "/internal/self-check", nil, http.StatusOK); err != nil {
		return err
	}
	return nil
}

func (c *selfCheckClient) command(path string, body any, expectedStatus int) error {
	raw, err := c.request(http.MethodPost, path, body, expectedStatus)
	if err != nil {
		return err
	}
	var incident store.EnvironmentIncident
	if err := decodeData(raw, &incident); err != nil {
		return err
	}
	if incident.IncidentID == "" || incident.Revision < 1 {
		return fmt.Errorf("命令响应缺少异常标识或 revision")
	}
	if c.incidentID != "" && incident.IncidentID != c.incidentID {
		return fmt.Errorf("异常标识在流程中发生变化")
	}
	c.incidentID, c.revision = incident.IncidentID, incident.Revision
	return nil
}

func (c *selfCheckClient) meta(requestID, actorID, role string) map[string]any {
	return map[string]any{"request_id": requestID, "actor_id": actorID, "actor_role": role, "expected_revision": c.revision}
}

func (c *selfCheckClient) reading(capturedAt time.Time, temperature, humidity float64, reference string) map[string]any {
	return map[string]any{"captured_at": capturedAt, "temperature_celsius": temperature, "relative_humidity_percent": humidity, "sensor_status": "ok", "calibration_reference": reference}
}

func (c *selfCheckClient) path(suffix string) string {
	return "/v1/environment-incidents/" + c.incidentID + suffix
}

func (c *selfCheckClient) request(method, path string, body any, expectedStatus int) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	c.requestCount++
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != expectedStatus {
		return nil, fmt.Errorf("%s %s 返回 %d，期望 %d：%s", method, path, response.StatusCode, expectedStatus, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func decodeData(data []byte, destination any) error {
	var envelope wireEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("解析响应外层: %w", err)
	}
	if err := json.Unmarshal(envelope.Data, destination); err != nil {
		return fmt.Errorf("解析响应数据: %w", err)
	}
	return nil
}
