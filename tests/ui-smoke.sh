#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ui_url=${AV_UI_URL:?AV_UI_URL is required}
ui_container=${AV_UI_CONTAINER:?AV_UI_CONTAINER is required}
# The test dependency is pinned in tests/ui/pnpm-lock.yaml and is installed in
# this Docker-only test image; AV's release image has no Node runtime.
image=av-ui-smoke:local

docker build --file "$root/tests/Dockerfile.ui-smoke" --tag "$image" "$root"

docker run --rm --pull never \
  --network "container:$ui_container" \
  --ipc host \
  --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=256m \
  --tmpfs /home/pwuser:rw,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --env AV_UI_URL="$ui_url" \
  --env AV_UI_EXPECT_MANAGED="${AV_UI_EXPECT_MANAGED:-}" \
  --env AV_UI_EXPECT_PROFILE="${AV_UI_EXPECT_PROFILE:-}" \
  --mount "type=bind,src=$root/tests/ui-smoke.mjs,dst=/test/ui-smoke.mjs,readonly" \
  "$image" \
  node /test/ui-smoke.mjs
