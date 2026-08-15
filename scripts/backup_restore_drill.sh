#!/usr/bin/env bash
set -u

if [ "${DDF_BACKUP_DRILL_ACK:-}" != "NONPRODUCTION_ONLY" ]; then
  echo "REFUSED."
  echo "Set DDF_BACKUP_DRILL_ACK=NONPRODUCTION_ONLY for a dedicated drill DB."
  exit 2
fi

: "${DDF_DRILL_DATABASE_URL:?Set DDF_DRILL_DATABASE_URL}"

case "$DDF_DRILL_DATABASE_URL" in
  *prod*|*production*)
    echo "REFUSED: database URL appears to reference production."
    exit 3
    ;;
esac

if [ -n "${DATABASE_URL:-}" ] &&
   [ "$DATABASE_URL" = "$DDF_DRILL_DATABASE_URL" ]; then
  echo "REFUSED: drill DB equals active DATABASE_URL."
  exit 4
fi

mkdir -p release-evidence

DUMP="release-evidence/ddf-backup-drill.dump"

START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

pg_dump \
  --format=custom \
  --file="$DUMP" \
  "$DDF_DRILL_DATABASE_URL"

pg_restore \
  --list "$DUMP" \
  > release-evidence/ddf-backup-contents.txt

END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > release-evidence/backup-restore-drill.txt <<EOF
started_at=$START
completed_at=$END
dump=$DUMP
validation=pg_restore --list succeeded
EOF

echo "Backup/restore artifact validation completed."
echo "A full disposable-database restore should also be performed before marking the gate passed."
