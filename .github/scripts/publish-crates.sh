#!/usr/bin/env bash
# Publishes the crates of this workspace to crates.io, in the order of the arguments. Give each crate
# after the crates that it depends on.
#
# crates.io limits the rate of publishes. A new crate has a burst of 5 and then 1 each 10 minutes. A
# new version of a crate has a burst of 30 and then 1 each minute. When crates.io refuses a publish
# for the rate, it gives a time to try again. This script waits until that time and tries again.
#
# A version that is already on crates.io is skipped. Thus a second run of the release workflow
# continues where the first run stopped.
#
# Usage: publish-crates.sh CRATE...

set -euo pipefail

# The longest wait for one retry, and the number of retries for one crate.
MAX_WAIT=900
MAX_TRIES=8

version=$(cargo metadata --format-version 1 --no-deps |
  jq -r '.packages[0].version')

# The path of a crate in the sparse index, per the crates.io index format.
index_path() {
  local name=${1,,}
  case ${#name} in
    1) echo "1/$name" ;;
    2) echo "2/$name" ;;
    3) echo "3/${name:0:1}/$name" ;;
    *) echo "${name:0:2}/${name:2:2}/$name" ;;
  esac
}

published() {
  curl --silent --fail --user-agent "publish-crates.sh ($GITHUB_REPOSITORY)" \
    "https://index.crates.io/$(index_path "$1")" 2>/dev/null |
    jq -e --arg v "$2" 'select(.vers == $v)' > /dev/null
}

# Gives the number of seconds until the time in a crates.io rate limit message, or 600 when the
# message has no time.
wait_seconds() {
  local when now at
  when=$(grep -o 'try again after [^o]*GMT' <<< "$1" | sed 's/try again after //' | head -n1 || true)
  if [ -z "$when" ] || ! at=$(date -u -d "$when" +%s 2>/dev/null); then
    echo 600
    return
  fi
  now=$(date -u +%s)
  local s=$((at - now + 15))
  [ "$s" -lt 15 ] && s=15
  [ "$s" -gt "$MAX_WAIT" ] && s=$MAX_WAIT
  echo "$s"
}

for crate in "$@"; do
  if published "$crate" "$version"; then
    echo "$crate $version is on crates.io. Skip."
    continue
  fi
  for try in $(seq 1 "$MAX_TRIES"); do
    echo "publish $crate $version, try $try"
    if out=$(cargo publish --package "$crate" --locked 2>&1); then
      echo "$out"
      break
    fi
    echo "$out"
    if published "$crate" "$version"; then
      echo "$crate $version is on crates.io."
      break
    fi
    if ! grep -qiE '429|too many|rate limit|try again after' <<< "$out"; then
      echo "::error::cargo publish failed for $crate, and the cause is not the rate limit"
      exit 1
    fi
    if [ "$try" -eq "$MAX_TRIES" ]; then
      echo "::error::crates.io refused $crate for the rate $MAX_TRIES times"
      exit 1
    fi
    s=$(wait_seconds "$out")
    echo "::notice::crates.io limits the rate. Wait $s seconds and try $crate again."
    sleep "$s"
  done
done
