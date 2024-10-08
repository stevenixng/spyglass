#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

docker run \
    --rm \
    --interactive \
    --tty \
    --publish 8080:5000 \
    --name spyglass \
    spyglass
