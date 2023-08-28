#!/usr/bin/env bash
set -xeuo pipefail

function getContainerCommand() {
    if command -v podman
    then
        CONTAINER_CMD=podman
    elif command -v docker
    then
        CONTAINER_CMD=docker
    else
        echo "ERROR: Container command not found"
        exit 2
    fi
    export CONTAINER_CMD
    echo "Running container using ${CONTAINER_CMD}"
}
getContainerCommand

export CONTAINER_BUILD_EXTRA_PARAMS=${CONTAINER_BUILD_EXTRA_PARAMS:-"--no-cache"}
export TICKET_SEARCH_IMAGE=${TICKET_SEARCH_IMAGE:-"quay.io/app-sre/ticket-search"}

# Tag with the current commit sha
export TICKET_SEARCH_TAG="$(git rev-parse --short=7 HEAD)"

# Setup credentials to image registry
${CONTAINER_CMD} login -u="${QUAY_USER}" -p="${QUAY_TOKEN}" quay.io

make build_image 

TICKET_SEARCH_IMAGE_LATEST="${TICKET_SEARCH_IMAGE}:latest"
${CONTAINER_CMD} tag "${TICKET_SEARCH_IMAGE}:${TICKET_SEARCH_TAG}" "${TICKET_SEARCH_IMAGE_LATEST}"

echo "Pushing images to quay..."
${CONTAINER_CMD} image ls "${TICKET_SEARCH_IMAGE}" --noheading 

${CONTAINER_CMD} push "${TICKET_SEARCH_IMAGE}:${TICKET_SEARCH_TAG}" 
${CONTAINER_CMD} push "${TICKET_SEARCH_IMAGE_LATEST}"