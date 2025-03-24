#!/bin/bash

# Run linters on the project
golangci-lint run -c ./_lint/.production.golangci.json "$@" 