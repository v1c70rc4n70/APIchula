#!/usr/bin/env bash
# Lanzador de escritorio para PurpleTeam KeyVault (Gestor Cifrado de API Keys).
# Arranca el servidor local en 127.0.0.1:8787 si no está activo y lo abre en ventana dedicada.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=8787
URL="http://127.0.0.1:${PORT}/"
SVC_PID=""

# Si no hay ya una instancia escuchando en el puerto 8787, la arrancamos en segundo plano
if ! ss -ltnH "sport = :${PORT}" 2>/dev/null | grep -q .; then
  python3 "$DIR/app.py" --host 127.0.0.1 --port "$PORT" >/dev/null 2>&1 &
  SVC_PID=$!
fi

cleanup() {
  if [[ -n "$SVC_PID" ]]; then
    kill "$SVC_PID" 2>/dev/null || true
    wait "$SVC_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Esperar a que el servidor esté listo (máx. 5 segundos)
for _ in {1..20}; do
  if ss -ltnH "sport = :${PORT}" 2>/dev/null | grep -q .; then
    break
  fi
  sleep 0.25
done

# Abrir en ventana tipo aplicación de Chrome/Chromium si está disponible, o en el navegador por defecto
if command -v google-chrome >/dev/null 2>&1; then
  google-chrome \
    --user-data-dir="$HOME/.config/apichula-keyvault-chrome" \
    --no-first-run \
    --no-default-browser-check \
    --app="$URL" >/dev/null 2>&1
elif command -v chromium >/dev/null 2>&1; then
  chromium \
    --user-data-dir="$HOME/.config/apichula-keyvault-chrome" \
    --no-first-run \
    --no-default-browser-check \
    --app="$URL" >/dev/null 2>&1
else
  xdg-open "$URL" >/dev/null 2>&1
  # Si se usa xdg-open (no bloqueante), mantenemos vivo el servidor
  if [[ -n "$SVC_PID" ]]; then
    wait "$SVC_PID"
  fi
fi
