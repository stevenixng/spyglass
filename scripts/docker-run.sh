#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

docker run \
    --rm \
    --interactive \
    --publish 8080:5000 /tcp \
    --name spyglass \
    spyglass
