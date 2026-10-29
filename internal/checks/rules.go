package checks

import (
	"fmt"
	"strings"
)

// Severity orders findings. INFO < LOW < MEDIUM < HIGH.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	}
	return "UNKNOWN"
}

// ParseSeverity accepts info, low, medium, high (any case) and "none".
// "none" returns a value above HIGH so nothing reaches it.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return Info, nil
	case "low":
		return Low, nil
	case "medium":
		return Medium, nil
	case "high":
		return High, nil
	case "none", "never":
		return High + 1, nil
	}
	return 0, fmt.Errorf("unknown severity %q (want info, low, medium, high or none)", s)
}

// Rule describes one check.
type Rule struct {
	ID          string
	Severity    Severity
	Title       string
	Remediation string
	// Refs are links to the upstream lines the rule is based on.
	Refs []string
}

const (
	dify    = "https://github.com/langgenius/dify/blob/1.17.1/"
	sandbox = "https://github.com/langgenius/dify-sandbox/blob/0.2.15/"
	daemon  = "https://github.com/langgenius/dify-plugin-daemon/blob/0.6.10/"
)

// Published defaults. These values are public in the Dify repository, so a
// deployment that still uses them has no secret at all.
const (
	LegacySecretKey    = "sk-9f73s3ljTXVcMT3Blb3ljTqtsKiGHXVcMT3BlbkFJLK7U"
	DefaultSandboxKey  = "dify-sandbox"
	DefaultDaemonKey   = "lYkiYYT6owG+71oLerGzA7GXCgOT++6ovaezWAjpCjf+Sjc3ZtU+qUEi"
	DefaultInnerAPIKey = "QaHbTe77CtuXmsfyhR7+vRjI/+XbV1AaFy691iy+kGDv2Jvy0/eAh8Y1"
	DefaultDBPassword  = "difyai123456"
	DefaultWeaviateKey = "WVF5YThaHlkYwhGUSmCRgsX3tD5ngdN8pkih"
	DefaultAgentSecret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"
	DefaultAgentToken  = "dify-agent-run-token-for-dev-only"
)

// Rules is the full catalogue, in report order.
var Rules = []Rule{
	{ID: "DSA001", Severity: High, Title: "SECRET_KEY is the value once published in .env.example",
		Remediation: "Set SECRET_KEY to a new random value (for example `openssl rand -base64 42`). Existing sessions and signed URLs become invalid.",
		Refs: []string{
			"https://github.com/langgenius/dify/blob/1.14.0/docker/.env.example#L104",
			dify + "api/libs/passport.py#L9",
			dify + "api/extensions/ext_set_secretkey.py#L6-L13",
		}},
	{ID: "DSA002", Severity: Info, Title: "SECRET_KEY is empty, so Dify generates and stores one",
		Remediation: "Fine for a single host. Back up the storage volume (it holds .dify_secret_key) and make sure every api/worker replica reads the same storage, or set SECRET_KEY explicitly.",
		Refs: []string{
			dify + "docker/.env.example#L33-L34",
			dify + "api/configs/secret_key.py#L12-L38",
			dify + "api/extensions/ext_set_secretkey.py#L6-L13",
		}},
	{ID: "DSA003", Severity: Low, Title: "SECRET_KEY is short or a placeholder",
		Remediation: "Use at least 32 random characters (`openssl rand -base64 42`). Dify's own generated key is secrets.token_urlsafe(48), 64 characters.",
		Refs:        []string{dify + "api/configs/secret_key.py#L28"}},
	{ID: "DSA004", Severity: Medium, Title: "INIT_PASSWORD is empty: whoever opens /install first becomes admin",
		Remediation: "Set INIT_PASSWORD before the first start, or finish setup before the site is reachable by anyone else.",
		Refs: []string{
			dify + "docker/.env.example#L35",
			dify + "api/extensions/ext_application_services.py#L693",
			dify + "api/services/init_validation_service.py#L33-L37",
			dify + "api/controllers/console/setup.py#L65-L93",
		}},
	{ID: "DSA005", Severity: Medium, Title: "Code sandbox uses the published API key dify-sandbox",
		Remediation: "Set SANDBOX_API_KEY and CODE_EXECUTION_API_KEY to the same new random value. Every container on ssrf_proxy_network (including plugin_daemon, which runs third-party plugins) can call the sandbox.",
		Refs: []string{
			dify + "docker/.env.example#L186",
			dify + "docker/.env.example#L194",
			dify + "docker/docker-compose.yaml#L523",
			sandbox + "internal/middleware/auth.go#L8-L15",
		}},
	{ID: "DSA006", Severity: Info, Title: "CODE_EXECUTION_API_KEY does not match the sandbox API key",
		Remediation: "Code nodes will fail with 401. Set both to the same value.",
		Refs:        []string{dify + "docker/.env.example#L186-L194", sandbox + "internal/middleware/auth.go#L11"}},
	{ID: "DSA007", Severity: Medium, Title: "Plugin daemon SERVER_KEY is the published default",
		Remediation: "Set PLUGIN_DAEMON_KEY to a new random value.",
		Refs:        []string{dify + "docker/.env.example#L225", dify + "docker/docker-compose.yaml#L597", daemon + ".env.example#L3"}},
	{ID: "DSA008", Severity: Medium, Title: "Inner API key for plugins is the published default",
		Remediation: "Set PLUGIN_DIFY_INNER_API_KEY to a new random value. nginx does not route /inner, so the key is reachable only from inside the Docker networks.",
		Refs:        []string{dify + "docker/.env.example#L235", dify + "docker/docker-compose.yaml#L239", dify + "docker/docker-compose.yaml#L601", dify + "docker/nginx/conf.d/default.conf.template"}},
	{ID: "DSA009", Severity: Medium, Title: "Database password is the published default difyai123456",
		Remediation: "Change DB_PASSWORD before the first start (the database keeps the password it was initialised with).",
		Refs:        []string{dify + "docker/.env.example#L77", dify + "docker/docker-compose.yaml#L432"}},
	{ID: "DSA010", Severity: Medium, Title: "Redis password is the published default difyai123456",
		Remediation: "Change REDIS_PASSWORD and the password inside CELERY_BROKER_URL together.",
		Refs:        []string{dify + "docker/.env.example#L102", dify + "docker/.env.example#L121", dify + "docker/docker-compose.yaml#L501"}},
	{ID: "DSA011", Severity: Medium, Title: "Weaviate API key is the published default",
		Remediation: "Set WEAVIATE_API_KEY and WEAVIATE_AUTHENTICATION_APIKEY_ALLOWED_KEYS to the same new random value.",
		Refs:        []string{dify + "docker/.env.example#L166", dify + "docker/.env.example#L175", dify + "docker/docker-compose.yaml#L834"}},
	{ID: "DSA012", Severity: Medium, Title: "Weaviate allows anonymous access",
		Remediation: "Set WEAVIATE_AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED=false. The compose fallback is false, but .env.example sets true.",
		Refs:        []string{dify + "docker/.env.example#L171", dify + "docker/docker-compose.yaml#L830"}},
	{ID: "DSA013", Severity: Medium, Title: "Datastore service uses a published default credential",
		Remediation: "Override the credential through its variable in .env (or edit the compose file where it is hard-coded).",
		Refs:        []string{dify + "docker/docker-compose.yaml#L856-L857", dify + "docker/docker-compose.yaml#L911", dify + "docker/docker-compose.yaml#L959", dify + "docker/docker-compose.yaml#L987"}},
	{ID: "DSA014", Severity: Medium, Title: "DIFY_AGENT_SERVER_SECRET_KEY is the development default",
		Remediation: "Generate a new value (`python -c 'import secrets; print(secrets.token_urlsafe(32))'`). Upstream marks it security-sensitive: it derives the JWE key for Agent Stub bearer tokens.",
		Refs:        []string{dify + "docker/.env.example#L278-L281", dify + "docker/docker-compose.yaml#L685"}},
	{ID: "DSA015", Severity: Medium, Title: "DIFY_AGENT_API_TOKEN is the development default",
		Remediation: "Generate a new value. Upstream: \"Replace this development default in production.\"",
		Refs:        []string{dify + "docker/.env.example#L257-L260", dify + "docker/docker-compose.yaml#L241", dify + "docker/docker-compose.yaml#L686"}},
	{ID: "DSA016", Severity: High, Title: "Outbound HTTP from the API bypasses ssrf_proxy",
		Remediation: "Set SSRF_PROXY_HTTP_URL and SSRF_PROXY_HTTPS_URL (or SSRF_PROXY_ALL_URL) to http://ssrf_proxy:3128. When neither form is complete Dify builds an httpx client without a proxy.",
		Refs:        []string{dify + "docker/.env.example#L202-L203", dify + "api/core/helper/ssrf_proxy.py#L86-L101"}},
	{ID: "DSA017", Severity: Low, Title: "SSRF proxy allows private destinations",
		Remediation: "Allow only the exact hosts or /32 addresses that must be reached. Broad ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16) re-open the Docker networks and cloud metadata.",
		Refs:        []string{dify + "docker/.env.example#L213-L219", dify + "docker/ssrf_proxy/docker-entrypoint.sh#L32-L56", dify + "docker/ssrf_proxy/squid.conf.template#L12-L13"}},
	{ID: "DSA018", Severity: Medium, Title: "Console API CORS allows any origin",
		Remediation: "Set CONSOLE_CORS_ALLOW_ORIGINS to the console URL (or leave it unset so CONSOLE_WEB_URL is used). The console blueprint is registered with supports_credentials=True.",
		Refs:        []string{dify + "docker/.env.example#L131", dify + "api/configs/feature/__init__.py#L586-L594", dify + "api/extensions/ext_blueprints.py#L92-L99"}},
	{ID: "DSA019", Severity: Low, Title: "Web app API CORS allows any origin",
		Remediation: "If the web apps are only served from your own domain, list it in WEB_API_CORS_ALLOW_ORIGINS. \"*\" is also the code default.",
		Refs:        []string{dify + "docker/.env.example#L130", dify + "api/configs/feature/__init__.py#L606-L614"}},
	{ID: "DSA020", Severity: Low, Title: "nginx serves plain HTTP",
		Remediation: "Set NGINX_HTTPS_ENABLED=true with a certificate, or terminate TLS in front of nginx and bind nginx to 127.0.0.1.",
		Refs:        []string{dify + "docker/.env.example#L285", dify + "docker/docker-compose.yaml#L793", dify + "docker/nginx/docker-entrypoint.sh#L5"}},
	{ID: "DSA021", Severity: Low, Title: "DEBUG is enabled",
		Remediation: "Set DEBUG=false in production.",
		Refs:        []string{dify + "docker/.env.example#L52", dify + "api/configs/deploy/__init__.py#L17-L20"}},
	{ID: "DSA022", Severity: Low, Title: "Request and response bodies are logged",
		Remediation: "Set ENABLE_REQUEST_LOGGING=false unless you are debugging; bodies can contain credentials and user data.",
		Refs:        []string{dify + "docker/.env.example#L54", dify + "api/configs/deploy/__init__.py#L22-L26"}},
	{ID: "DSA023", Severity: Low, Title: "Console pages may be framed by other sites",
		Remediation: "Keep ALLOW_EMBED=false unless you embed the console on purpose. Published app routes stay embeddable either way.",
		Refs:        []string{dify + "docker/.env.example#L143", dify + "docker/docker-compose.yaml#L409", dify + "web/proxy.ts#L51-L60"}},
	{ID: "DSA024", Severity: Medium, Title: "Plugin signature verification is disabled",
		Remediation: "Set FORCE_VERIFYING_SIGNATURE=true so only signed plugins can be installed.",
		Refs:        []string{dify + "docker/.env.example#L237", dify + "docker/docker-compose.yaml#L605", daemon + ".env.example#L210-L212"}},
	{ID: "DSA025", Severity: Low, Title: "Plugin daemon pprof is enabled",
		Remediation: "Set PLUGIN_PPROF_ENABLED=false.",
		Refs:        []string{dify + "docker/.env.example#L230", dify + "docker/docker-compose.yaml#L599"}},

	{ID: "DSA101", Severity: Medium, Title: "Port published on all host interfaces",
		Remediation: "Prefix the mapping with a host IP, e.g. \"127.0.0.1:5003:5003\", or remove the mapping. Ports published by Docker are not filtered by ufw/firewalld INPUT rules by default.",
		Refs:        []string{dify + "docker/docker-compose.yaml#L641-L642", dify + "docker/docker-compose.yaml#L812-L814", daemon + "internal/types/app/config.go#L103"}},
	{ID: "DSA102", Severity: High, Title: "Service runs privileged",
		Remediation: "Remove privileged: true; add only the capabilities the image needs.",
		Refs:        []string{dify + "docker/docker-compose.yaml#L1182"}},
	{ID: "DSA103", Severity: High, Title: "Docker socket mounted into a container",
		Remediation: "Remove the docker.sock mount; it gives root on the host to anything that compromises the container."},
	{ID: "DSA104", Severity: Medium, Title: "Service uses the host network",
		Remediation: "Remove network_mode: host and publish only the ports needed, bound to 127.0.0.1."},
	{ID: "DSA105", Severity: High, Title: "Code sandbox is on a network with direct internet access",
		Remediation: "Attach sandbox only to ssrf_proxy_network (internal: true), as upstream does, so its egress must go through ssrf_proxy.",
		Refs:        []string{dify + "docker/docker-compose.yaml#L536-L537", dify + "docker/docker-compose.yaml#L1302-L1304"}},
}

// RuleByID returns the rule with id, or nil.
func RuleByID(id string) *Rule {
	for i := range Rules {
		if Rules[i].ID == id {
			return &Rules[i]
		}
	}
	return nil
}
