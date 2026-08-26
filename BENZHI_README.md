# BENZHI_README

## 项目说明
- 项目：benzhi-project-706c8483-f15f-42c4-8a50-77c1c2216635
- 项目用途：已完整实现展柜微环境异常复原服务，通过 HTTP JSON API 编排异常登记、风险分级、现场复核、干预审核、执行校准、恢复观察、主管签署与不可变审计证据封存。
- Go 工具链：`golang:1.23`
- 前端工具链：无

## 项目描述
- 项目名称：展柜微环境异常复原台
- 项目介绍：面向博物馆藏品保护人员的展柜微环境异常处置服务，记录异常、评估风险、执行干预、验证恢复并完成重新开放与证据封存。
- 项目概述：面向博物馆藏品保护人员的展柜微环境异常处置服务，记录异常、评估风险、执行干预、验证恢复并完成重新开放与证据封存。
- 核心工作流：展柜微环境异常发现后，经过风险评估、现场核查、干预审核、执行校验、恢复观察，最终由主管签署重新开放并封存全过程证据。
- 对外接口：HTTP JSON API，提供异常事件、核查、干预、验证和签署资源；服务支持 -addr=127.0.0.1:<port> 或 PORT 环境变量，默认监听 127.0.0.1:19081。

## 标准构建、运行和测试命令
进入容器后执行：
cd '/app' && GOTOOLCHAIN=local go build ./...

cd /app && GOTOOLCHAIN=local go run ./cmd/server -self-check -addr=127.0.0.1:19081

cd '/app' && GOTOOLCHAIN=local go test ./...

## Docker 构建和进入容器
chmod +x build_benzhi_docker.sh

./build_benzhi_docker.sh benzhi-project-706c8483-f15f-42c4-8a50-77c1c2216635-amd64 linux/amd64

./build_benzhi_docker.sh benzhi-project-706c8483-f15f-42c4-8a50-77c1c2216635-arm64 linux/arm64

docker run -it benzhi-project-706c8483-f15f-42c4-8a50-77c1c2216635-amd64:latest

## 题目验证命令
1. 预期退出码 0：`go test ./...`
2. 预期退出码 0：`go run ./cmd/server -self-check -addr=127.0.0.1:19081`
