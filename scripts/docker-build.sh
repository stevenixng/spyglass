#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

docker build -t spyglass:latest -f Dockerfile .
