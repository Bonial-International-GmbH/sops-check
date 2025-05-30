.DEFAULT_GOAL := help

TEST_FLAGS ?= -race
PKGS       ?= $(shell go list ./... | grep -v /vendor/)
BINARY     := sops-check
IMAGE      ?= sops-check
TAG        ?= latest

.PHONY: all clean

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build        - Build the sops-check binary (rebuilds if any Go file or go.mod/go.sum changes)"
	@echo "  demo         - Run sops-check on the demo directory using demo/.sops-check.yaml"
	@echo "  docker-build - Build the sops-check Docker image"
	@echo "  test         - Run all Go tests with race detection"
	@echo "  vet          - Run go vet on all packages"
	@echo "  coverage     - Generate code coverage report"
	@echo "  lint         - Run golangci-lint on the codebase"
	@echo "  serve        - Serve documentation locally via mkdocs"
	@echo ""
	@echo "The demo includes:"
	@echo "  - Good examples in demo/good/"
	@echo "  - Bad examples in demo/bad/"
	@echo "  - Configuration in demo/.sops-check.yaml"

.PHONY: build
build: $(BINARY)

$(BINARY): $(shell find . -type f -name '*.go') go.mod go.sum
	go build \
		-ldflags "-s -w" \
		-o $(BINARY) \
		main.go

.PHONY: docker-build
docker-build: ## build docker image
	docker build -t $(IMAGE):$(TAG) .

.PHONY: test
test: ## run tests
	go test $(TEST_FLAGS) $(PKGS)

.PHONY: vet
vet: ## run go vet
	go vet $(PKGS)

.PHONY: coverage
coverage: ## generate code coverage
	go test $(TEST_FLAGS) -covermode=atomic -coverprofile=coverage.txt $(PKGS)
	go tool cover -func=coverage.txt

.PHONY: lint
lint: ## run golangci-lint
	golangci-lint run

.PHONY: serve
serve: ## serve documentation locally via mkdocs
	mkdocs serve

.PHONY: demo

# Demo target
demo: $(BINARY)
	@echo "Running sops-check on demo directory..."
	@./$(BINARY) --config demo/.sops-check.yaml demo
