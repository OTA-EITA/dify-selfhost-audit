#!/usr/bin/env bash
# Live probes against a default Dify stack. Meant to run ONLY on a disposable
# GitHub-hosted runner from .github/workflows/dify-lab.yml, never on a
# workstation or server. It reads status codes only; it never prints response
# bodies from the metadata address.
#
# Usage: probe.sh <dify docker dir> <override file> <results.md>
set -uo pipefail

DIR=$1
OVERRIDE=$2
OUT=$3
cd "$DIR" || exit 2

dc() { docker compose -p difylab -f docker-compose.yaml -f "$OVERRIDE" "$@"; }

# Run curl inside the api container (it ships curl for its healthcheck and
# sits on both ssrf_proxy_network and default).
in_api() { dc exec -T api curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" 2>/dev/null || true; }

{
  echo "| Probe | Expected (default 1.17.1) | Observed | Result |"
  echo "|---|---|---|---|"
} > "$OUT"

row() { # probe expected observed pass|fail|info
  local mark
  case $4 in pass) mark="as expected" ;; fail) mark="**differs**" ;; *) mark="info" ;; esac
  printf '| %s | %s | `%s` | %s |\n' "$1" "$2" "$3" "$mark" >> "$OUT"
}

check() { # probe expected-value observed
  if [ "$2" = "$3" ]; then row "$1" "$2" "$3" pass; else row "$1" "$2" "$3" fail; fi
}

# --- 1. Published ports -----------------------------------------------------
listeners=$(ss -ltnH 2>/dev/null | awk '{print $4}' | grep -E ':(80|443|5003)$' | sort -u | tr '\n' ' ')
row "Host listeners on :80/:443/:5003 (lab binds 127.0.0.1)" "127.0.0.1 only" "${listeners:-none}" info
check "nginx via 127.0.0.1:80 /console/api/setup" "200" \
  "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1/console/api/setup || true)"
if timeout 5 bash -c '</dev/tcp/127.0.0.1/5003' 2>/dev/null; then p5003=open; else p5003=closed; fi
check "plugin_daemon debug port 127.0.0.1:5003 accepts TCP" "open" "$p5003"
hostip=$(hostname -I | awk '{print $1}')
if timeout 5 bash -c "</dev/tcp/$hostip/5003" 2>/dev/null; then ext=open; else ext=closed; fi
check "Debug port on runner's non-loopback IP ($hostip:5003)" "closed" "$ext"

# --- 2. Sandbox API key ------------------------------------------------------
DEP='http://sandbox:8194/v1/sandbox/dependencies?language=python3'
check "sandbox with X-Api-Key: dify-sandbox" "200" "$(in_api -H 'X-Api-Key: dify-sandbox' "$DEP")"
check "sandbox with a wrong key" "401" "$(in_api -H 'X-Api-Key: wrong-key' "$DEP")"
check "sandbox with no key" "401" "$(in_api "$DEP")"
# Same call from the plugin_daemon container, which runs third-party plugins.
pd=$(dc exec -T plugin_daemon sh -c "command -v curl >/dev/null && curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'X-Api-Key: dify-sandbox' '$DEP' || echo no-curl" 2>/dev/null || echo exec-failed)
row "sandbox reachable from plugin_daemon with default key" "200 (same network)" "$pd" info

# --- 3. ssrf_proxy -----------------------------------------------------------
P='http://ssrf_proxy:3128'
check "via ssrf_proxy: http://169.254.169.254/ (metadata)" "403" "$(in_api -x "$P" http://169.254.169.254/)"
check "via ssrf_proxy: http://api:5001/health" "403" "$(in_api -x "$P" http://api:5001/health)"
check "via ssrf_proxy: http://sandbox:8194/health" "403" "$(in_api -x "$P" http://sandbox:8194/health)"
check "via ssrf_proxy: http://plugin_daemon:5002/" "403" "$(in_api -x "$P" http://plugin_daemon:5002/)"
check "via ssrf_proxy: http://weaviate:8080/v1/meta" "403" "$(in_api -x "$P" http://weaviate:8080/v1/meta)"
check "via ssrf_proxy: http://127.0.0.1:3128/ (proxy itself)" "403" "$(in_api -x "$P" http://127.0.0.1:3128/)"
row "via ssrf_proxy: https://example.com/ (public, control)" "200" "$(in_api -x "$P" https://example.com/)" info
row "api direct (no proxy): http://sandbox:8194/health" "200 (same network)" "$(in_api --noproxy '*' http://sandbox:8194/health)" info

# Code inside the sandbox: the proxy is only an environment variable, so try
# a direct connection that ignores it, and one that goes through it.
PY=$(cat <<'EOF'
import urllib.request
def probe(url, use_env_proxy):
    handlers = [] if use_env_proxy else [urllib.request.ProxyHandler({})]
    try:
        r = urllib.request.build_opener(*handlers).open(url, timeout=5)
        return str(r.status)
    except urllib.error.HTTPError as e:
        return str(e.code)
    except Exception as e:
        return type(e).__name__
print("direct_api=" + probe("http://api:5001/health", False))
print("direct_daemon=" + probe("http://plugin_daemon:5002/", False))
print("proxy_metadata=" + probe("http://169.254.169.254/", True))
EOF
)
body=$(jq -cn --arg code "$PY" '{language:"python3", code:$code, preload:"", enable_network:true}')
res=$(printf '%s' "$body" | dc exec -T api curl -s --max-time 30 -H 'X-Api-Key: dify-sandbox' \
  -H 'Content-Type: application/json' --data-binary @- http://sandbox:8194/v1/sandbox/run 2>/dev/null || true)
stdout=$(printf '%s' "$res" | jq -r '.data.stdout // .message // "no-response"' 2>/dev/null | tr '\n' ' ')
row "sandboxed code, enable_network=true: direct to api/plugin_daemon, proxied to metadata" "see note" "${stdout:-no-response}" info

# --- 4. First-run setup without INIT_PASSWORD -------------------------------
setup=$(curl -s --max-time 10 http://127.0.0.1/console/api/setup | jq -r '.step // "?"' 2>/dev/null)
check "GET /console/api/setup before any admin exists" "not_started" "$setup"
init=$(curl -s --max-time 10 http://127.0.0.1/console/api/init | jq -r '.status // "?"' 2>/dev/null)
check "GET /console/api/init with INIT_PASSWORD empty (no password step)" "finished" "$init"

echo "probe.sh done" >&2
