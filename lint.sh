#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <filename>"
  exit 1
fi

# Run the linter on the whole package but grep only for the specified file
golangci-lint -c ./.golangci.json run "$@"