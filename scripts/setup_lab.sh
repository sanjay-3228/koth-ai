#!/bin/bash
set -euo pipefail

BASE="/home/bipin/koth-ai"
cd "$BASE"

echo "=== 1. Installing scoped sudoers policy ==="
cp "$BASE/config/koth-docker.sudoers" /etc/sudoers.d/koth-docker
chmod 0440 /etc/sudoers.d/koth-docker
visudo -cf /etc/sudoers.d/koth-docker

echo "=== 2. Creating internal koth-lab network ==="
if ! docker network inspect koth-lab >/dev/null 2>&1; then
  docker network create \
    --driver bridge \
    --internal \
    --subnet=172.28.0.0/16 \
    koth-lab
fi
docker network inspect koth-lab \
  --format 'Internal={{.Internal}} Driver={{.Driver}} Subnet={{range .IPAM.Config}}{{.Subnet}}{{end}}'

echo "=== 3. Building images ==="
docker build -t target-01:latest ./targets/target-01
docker build -t koth-runner:latest ./sandbox/koth-runner

echo "=== 4. Starting koth-target-01 container ==="
docker rm -f koth-target-01 2>/dev/null || true
docker run -d \
  --name koth-target-01 \
  --network koth-lab \
  target-01:latest

echo "=== 5. Verifying target container status ==="
docker inspect koth-target-01 \
  --format 'Status={{.State.Status}} NetworkMode={{.HostConfig.NetworkMode}}'
docker inspect koth-target-01 \
  --format '{{json .NetworkSettings.Networks}}'

echo "=== 6. Setup completed successfully ==="
