BINARY := qqdump
OUT     := bin
GOFLAGS ?= -trimpath

.PHONY: all build test fmt vet proto sample e2e clean

all: fmt vet test build

build:
	go build $(GOFLAGS) -o $(OUT)/$(BINARY) ./cmd/qqdump

# 单元测试（不需要任何外部工具）
test:
	go test ./...

fmt:
	gofmt -l -w .

vet:
	go vet ./...

# 从 proto 重新生成 Go 代码（需要 buf 与 protoc-gen-go）
proto:
	buf generate

# 生成端到端测试样本（需要系统里有 sqlcipher CLI）
sample:
	python3 tools/make_sample.py

# 端到端：造样本 → 解密 → 导出。密钥与样本生成脚本一致。
e2e: build sample
	rm -rf /tmp/qqdump-e2e
	./$(OUT)/$(BINARY) export \
		-i testdata/nt_msg_sample.db \
		-u u_test1234abcd \
		-o /tmp/qqdump-e2e
	ls -l /tmp/qqdump-e2e

clean:
	rm -rf $(OUT)
