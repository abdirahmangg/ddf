#!/usr/bin/env bash
set -u

if [ "${DDF_CHAOS_ACK:-}" != "NONPRODUCTION_ONLY" ]; then
  echo "REFUSED."
  echo "Set DDF_CHAOS_ACK=NONPRODUCTION_ONLY only for a dedicated drill environment."
  exit 2
fi

: "${DDF_CHAOS_NAMESPACE:?Set DDF_CHAOS_NAMESPACE}"
: "${DDF_CHAOS_BASE_URL:?Set DDF_CHAOS_BASE_URL}"

CONTEXT="$(kubectl config current-context)"

echo "Context:   $CONTEXT"
echo "Namespace: $DDF_CHAOS_NAMESPACE"
echo "URL:       $DDF_CHAOS_BASE_URL"

case "$CONTEXT" in
  *prod*|*production*)
    echo "REFUSED: Kubernetes context appears to be production."
    exit 3
    ;;
esac

mkdir -p release-evidence

python scripts/load_probe.py \
  --url "${DDF_CHAOS_BASE_URL}/ready/dependencies" \
  --requests 500 \
  --concurrency 20 \
  --output /tmp/ddf-before-chaos.json

POD="$(
  kubectl \
    -n "$DDF_CHAOS_NAMESPACE" \
    get pods \
    -l app=ddf \
    -o jsonpath='{.items[0].metadata.name}'
)"

if [ -z "$POD" ]; then
  echo "No DDF pod found."
  exit 4
fi

echo "Deleting drill pod: $POD"

kubectl \
  -n "$DDF_CHAOS_NAMESPACE" \
  delete pod "$POD" \
  --wait=false

python scripts/load_probe.py \
  --url "${DDF_CHAOS_BASE_URL}/ready/dependencies" \
  --requests 1500 \
  --concurrency 40 \
  --output release-evidence/load-results.json

kubectl \
  -n "$DDF_CHAOS_NAMESPACE" \
  rollout status deployment/ddf \
  --timeout=180s

kubectl \
  -n "$DDF_CHAOS_NAMESPACE" \
  get pods \
  -l app=ddf \
  -o wide \
  > release-evidence/ha-after-chaos.txt

echo "HA/chaos drill completed."
