.PHONY: all deps lint test vet
CHECK_FILES?=$$(go list ./... | grep -v /vendor/)

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: lint vet deps test ## Run tests and linters.

deps: ## Install dependencies.
	go get -u github.com/golang/dep && dep ensure -update

lint: ## Lint the code.
	golint $(CHECK_FILES)

test: ## Run tests.
	go test -p 1 -v ./...

vet: # Vet the code
	go vet $(CHECK_FILES)
