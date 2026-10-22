#!/bin/sh
set -eu
umask 077
if [ -e .env ]; then
  echo '.env already exists; leaving it unchanged.'
  exit 0
fi
python3 - <<'PY'
import secrets
from pathlib import Path
Path('.env').write_text('ADMIN_TOKEN=' + secrets.token_urlsafe(48) + '\nGRAFANA_PASSWORD=' + secrets.token_urlsafe(24) + '\n')
PY
printf 'Created local secrets in .env (excluded from git).\n'
