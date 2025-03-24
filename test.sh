#!/bin/bash

# Run linters on the project
golangci-lint run -c ./_lint/.production.golangci.json . && \
go test -v -race -coverpkg=. -coverprofile=coverage.txt -covermode=atomic ./... && \
gosec -no-fail -fmt sarif -out gosec-results.sarif ./... && \
govulncheck ./... && \
go vet ./... 


