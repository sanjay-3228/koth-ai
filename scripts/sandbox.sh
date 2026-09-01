#!/bin/bash

set -euo pipefail

IMAGE="koth-runner:latest"
NAME="koth-session"

sudo docker run --rm -it \
    --name "$NAME" \
    --cap-drop=ALL \
    --security-opt=no-new-privileges:true \
    --pids-limit=512 \
    --memory=2g \
    --cpus=2 \
    --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=512m \
    --tmpfs /run:rw,nosuid,nodev,noexec,size=64m \
    --network=none \
    "$IMAGE"
