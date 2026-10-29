// Package checks turns a parsed env file and compose project into findings.
package checks

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/OTA-EITA/dify-selfhost-audit/internal/compose"
	"github.com/OTA-EITA/dify-selfhost-audit/internal/envfile"
)

// Finding is one problem at one place.
type Finding struct {
	RuleID   string
	Severity Severity
	Title    string
	Message  string
	Service  string
	File     string
	Line     int
}

// Input is what the checks look at. Env is the merged project env (the
// --env files). Project is nil when no compose file was given.
type Input struct {
	Env         *envfile.Env
	Project     *compose.Project
	AllProfiles bool
}

// Result holds findings plus context for the report.
type Result struct {
	Findings []Finding
	// Skipped lists services not evaluated because their profile is off.
	Skipped []string
}

// Run evaluates every rule.
func Run(in Input) Result {
	if in.Env == nil {
		in.Env = envfile.New()
	}
	c := &ctx{in: in}
	if in.Project != nil {
		for _, s := range in.Project.Services {
			if !c.active(s) {
				c.res.Skipped = append(c.res.Skipped, s.Name)
			}
		}
	}

	c.secretKey()
	c.initPassword()
	c.sandboxKey()
	c.defaultValue("DSA007", "plugin_daemon", "SERVER_KEY", "PLUGIN_DAEMON_KEY", DefaultDaemonKey)
	c.defaultValue("DSA008", "api", "INNER_API_KEY_FOR_PLUGIN", "PLUGIN_DIFY_INNER_API_KEY", DefaultInnerAPIKey)
	c.defaultValue("DSA009", "api", "DB_PASSWORD", "DB_PASSWORD", DefaultDBPassword)
	c.defaultValue("DSA010", "api", "REDIS_PASSWORD", "REDIS_PASSWORD", DefaultDBPassword)
	c.brokerURL()
	c.weaviate()
	c.datastoreDefaults()
	c.defaultValue("DSA014", "agent_backend", "DIFY_AGENT_SERVER_SECRET_KEY", "DIFY_AGENT_SERVER_SECRET_KEY", DefaultAgentSecret)
	c.defaultValue("DSA015", "agent_backend", "DIFY_AGENT_API_TOKEN", "DIFY_AGENT_API_TOKEN", DefaultAgentToken)
	c.ssrfProxy()
	c.ssrfAllowPrivate()
	c.cors()
	c.flag("DSA020", "nginx", "NGINX_HTTPS_ENABLED", "NGINX_HTTPS_ENABLED", "false", false)
	c.flag("DSA021", "api", "DEBUG", "DEBUG", "", true)
	c.flag("DSA022", "api", "ENABLE_REQUEST_LOGGING", "ENABLE_REQUEST_LOGGING", "", true)
	c.flag("DSA023", "web", "ALLOW_EMBED", "ALLOW_EMBED", "false", true)
	c.flag("DSA024", "plugin_daemon", "FORCE_VERIFYING_SIGNATURE", "FORCE_VERIFYING_SIGNATURE", "true", false)
	c.flag("DSA025", "plugin_daemon", "PPROF_ENABLED", "PLUGIN_PPROF_ENABLED", "false", true)

	if in.Project != nil {
		c.ports()
		c.privileged()
		c.dockerSock()
		c.hostNetwork()
		c.sandboxNetwork()
	}

	sort.SliceStable(c.res.Findings, func(i, j int) bool {
		a, b := c.res.Findings[i], c.res.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.RuleID < b.RuleID
	})
	return c.res
}

type ctx struct {
	in  Input
	res Result
}

func (c *ctx) active(s *compose.Service) bool {
	return c.in.AllProfiles || s.Active(c.in.Project.Profiles)
}

// setting is a resolved value and where it was decided.
type setting struct {
	value   string
	set     bool
	file    string
	line    int
	service string
}

// get resolves a container setting. With a compose file it reads the
// service's effective environment; without one it reads envKey from the env
// files. ok is false when the service exists but is not started.
func (c *ctx) get(service, containerKey, envKey string) (setting, bool) {
	if p := c.in.Project; p != nil {
		s := p.Service(service)
		if s != nil {
			if !c.active(s) {
				return setting{}, false
			}
			if v, ok := s.Env[containerKey]; ok {
				return setting{value: v.Value, set: true, file: v.File, line: v.Line, service: service}, true
			}
			return setting{service: service, file: p.File, line: s.Line}, true
		}
	}
	if e, ok := c.in.Env.Get(envKey); ok {
		return setting{value: e.Value, set: true, file: e.File, line: e.Line, service: service}, true
	}
	return setting{service: service}, true
}

func (c *ctx) add(id string, st setting, msg string) {
	r := RuleByID(id)
	if r == nil {
		panic("unknown rule " + id)
	}
	c.res.Findings = append(c.res.Findings, Finding{
		RuleID: r.ID, Severity: r.Severity, Title: r.Title, Message: msg,
		Service: st.service, File: st.file, Line: st.line,
	})
}

// Mask shows enough of a secret to recognise it without printing it.
func Mask(s string) string {
	if s == "" {
		return `""`
	}
	if len(s) <= 6 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 4) + fmt.Sprintf(" (%d chars)", len(s))
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "t", "yes", "y", "on":
		return true
	}
	return false
}

var placeholderSecrets = map[string]bool{
	"changeme": true, "change-me": true, "secret": true, "secret_key": true,
	"your-secret-key": true, "your_secret_key": true, "please-change-me": true,
	"dify": true, "password": true, "difyai123456": true,
}

func (c *ctx) secretKey() {
	st, ok := c.get("api", "SECRET_KEY", "SECRET_KEY")
	if !ok {
		return
	}
	switch v := st.value; {
	case v == LegacySecretKey:
		c.add("DSA001", st, "SECRET_KEY equals the value shipped in docker/.env.example up to 1.14.0. Anyone can sign session JWTs for this instance.")
	case strings.TrimSpace(v) == "":
		c.add("DSA002", st, "SECRET_KEY is empty. At 1.17.1 the API generates a key and saves it as .dify_secret_key in its storage.")
	case placeholderSecrets[strings.ToLower(v)] || len(v) < 32:
		c.add("DSA003", st, fmt.Sprintf("SECRET_KEY is %s; expected at least 32 random characters.", Mask(v)))
	}
}

func (c *ctx) initPassword() {
	st, ok := c.get("api", "INIT_PASSWORD", "INIT_PASSWORD")
	if ok && strings.TrimSpace(st.value) == "" {
		c.add("DSA004", st, "INIT_PASSWORD is empty, so POST /console/api/setup needs no password until the first admin exists.")
	}
}

func (c *ctx) sandboxKey() {
	sb, ok := c.get("sandbox", "API_KEY", "SANDBOX_API_KEY")
	if !ok {
		return
	}
	if !sb.set && c.in.Project == nil {
		sb.value = DefaultSandboxKey // compose fallback ${SANDBOX_API_KEY:-dify-sandbox}
	}
	if sb.value == DefaultSandboxKey {
		c.add("DSA005", sb, "The sandbox accepts X-Api-Key: dify-sandbox.")
	}
	api, ok := c.get("api", "CODE_EXECUTION_API_KEY", "CODE_EXECUTION_API_KEY")
	if ok && api.set && api.value != sb.value {
		c.add("DSA006", api, fmt.Sprintf("api sends %s but sandbox expects %s.", Mask(api.value), Mask(sb.value)))
	}
}

// defaultValue flags a setting equal to a published default. When there is
// no compose file and the variable is absent, the compose fallback (which is
// the same published default) applies.
func (c *ctx) defaultValue(id, service, containerKey, envKey, def string) {
	st, ok := c.get(service, containerKey, envKey)
	if !ok {
		return
	}
	if !st.set && c.in.Project == nil {
		st.value = def
	}
	if st.value == def {
		where := envKey
		if c.in.Project != nil {
			where = service + " " + containerKey
		}
		c.add(id, st, fmt.Sprintf("%s is the published default %s.", where, Mask(def)))
	}
}

func (c *ctx) brokerURL() {
	st, ok := c.get("api", "CELERY_BROKER_URL", "CELERY_BROKER_URL")
	if ok && strings.Contains(st.value, ":"+DefaultDBPassword+"@") {
		c.add("DSA010", st, "CELERY_BROKER_URL still contains the default Redis password.")
	}
}

func (c *ctx) weaviateInUse() bool {
	if p := c.in.Project; p != nil {
		s := p.Service("weaviate")
		return s != nil && c.active(s)
	}
	v, ok := c.in.Env.Lookup("VECTOR_STORE")
	return !ok || v == "" || v == "weaviate"
}

func (c *ctx) weaviate() {
	if !c.weaviateInUse() {
		return
	}
	if st, ok := c.get("weaviate", "AUTHENTICATION_APIKEY_ALLOWED_KEYS", "WEAVIATE_AUTHENTICATION_APIKEY_ALLOWED_KEYS"); ok {
		if !st.set && c.in.Project == nil {
			st.value = DefaultWeaviateKey
		}
		for _, k := range strings.Split(st.value, ",") {
			if strings.TrimSpace(k) == DefaultWeaviateKey {
				c.add("DSA011", st, "Weaviate accepts the published API key.")
				break
			}
		}
	}
	if st, ok := c.get("weaviate", "AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED", "WEAVIATE_AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED"); ok && truthy(st.value) {
		c.add("DSA012", st, "Requests without an API key are accepted by Weaviate.")
	}
}

// Services covered by dedicated rules; DSA013 handles the rest.
var coveredServices = map[string]bool{
	"api": true, "api_websocket": true, "worker": true, "worker_beat": true, "web": true,
	"db_postgres": true, "db_mysql": true, "redis": true, "weaviate": true,
	"sandbox": true, "plugin_daemon": true, "agent_backend": true, "local_sandbox": true,
}

// Credentials that appear as defaults or hard-coded values in the upstream
// compose file for optional datastores.
var knownDatastoreDefaults = map[string]bool{
	"difyai123456": true, "Difyai123456": true, "password": true, "minioadmin": true,
	"Qazwsxedc!@#123": true, "Dify@123": true, "elastic": true,
}

func secretish(key string) bool {
	k := strings.ToUpper(key)
	for _, w := range []string{"PASSWORD", "SECRET", "API_KEY", "ACCESS_KEY", "TOKEN"} {
		if strings.Contains(k, w) {
			return true
		}
	}
	return false
}

func (c *ctx) datastoreDefaults() {
	p := c.in.Project
	if p == nil {
		return
	}
	for _, s := range p.Services {
		if coveredServices[s.Name] || !c.active(s) {
			continue
		}
		keys := make([]string, 0, len(s.Env))
		for k := range s.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := s.Env[k]
			if secretish(k) && knownDatastoreDefaults[v.Value] {
				c.add("DSA013", setting{value: v.Value, set: true, file: v.File, line: v.Line, service: s.Name},
					fmt.Sprintf("%s %s is a published default (%s).", s.Name, k, Mask(v.Value)))
			}
		}
	}
}

func (c *ctx) ssrfProxy() {
	services := []string{"api", "worker"}
	if c.in.Project == nil {
		services = []string{"api"}
	}
	for _, svc := range services {
		all, ok := c.get(svc, "SSRF_PROXY_ALL_URL", "SSRF_PROXY_ALL_URL")
		if !ok {
			continue
		}
		if c.in.Project != nil && c.in.Project.Service(svc) == nil {
			continue
		}
		httpURL, _ := c.get(svc, "SSRF_PROXY_HTTP_URL", "SSRF_PROXY_HTTP_URL")
		httpsURL, _ := c.get(svc, "SSRF_PROXY_HTTPS_URL", "SSRF_PROXY_HTTPS_URL")
		if strings.TrimSpace(all.value) != "" {
			continue
		}
		if strings.TrimSpace(httpURL.value) != "" && strings.TrimSpace(httpsURL.value) != "" {
			continue
		}
		st := httpURL
		if st.set && strings.TrimSpace(st.value) != "" {
			st = httpsURL
		}
		c.add("DSA016", st, fmt.Sprintf("%s: SSRF_PROXY_ALL_URL is empty and SSRF_PROXY_HTTP_URL/SSRF_PROXY_HTTPS_URL are not both set, so HTTP request nodes and tools connect directly.", svc))
	}
}

var (
	linkLocal4 = netip.MustParsePrefix("169.254.0.0/16")
	loopback4  = netip.MustParsePrefix("127.0.0.0/8")
	linkLocal6 = netip.MustParsePrefix("fe80::/10")
	loopback6  = netip.MustParsePrefix("::1/128")
)

func (c *ctx) ssrfAllowPrivate() {
	for _, key := range []string{"SSRF_PROXY_ALLOW_PRIVATE_IPS", "SSRF_PROXY_ALLOW_PRIVATE_DOMAINS"} {
		st, ok := c.get("ssrf_proxy", key, key)
		if !ok || strings.TrimSpace(st.value) == "" {
			continue
		}
		msg := fmt.Sprintf("%s=%s lets requests through ssrf_proxy to these private targets.", key, st.value)
		if key == "SSRF_PROXY_ALLOW_PRIVATE_IPS" {
			if wide := wideEntries(st.value); len(wide) > 0 {
				msg += fmt.Sprintf(" Overlaps sensitive ranges: %s.", strings.Join(wide, ", "))
			}
		}
		c.add("DSA017", st, msg)
	}
}

// wideEntries returns the entries that are IPv4 /16 or larger, IPv6 /64 or
// larger, or that overlap link-local (cloud metadata) or loopback space.
func wideEntries(v string) []string {
	var out []string
	for _, raw := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			a, err2 := netip.ParseAddr(raw)
			if err2 != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		p = p.Masked()
		wide := (p.Addr().Is4() && p.Bits() <= 16) || (p.Addr().Is6() && p.Bits() <= 64)
		for _, b := range []netip.Prefix{linkLocal4, loopback4, linkLocal6, loopback6} {
			if b.Overlaps(p) {
				wide = true
			}
		}
		if wide {
			out = append(out, raw)
		}
	}
	return out
}

func hasStar(v string) bool {
	for _, o := range strings.Split(v, ",") {
		if strings.TrimSpace(o) == "*" {
			return true
		}
	}
	return false
}

func (c *ctx) cors() {
	if st, ok := c.get("api", "CONSOLE_CORS_ALLOW_ORIGINS", "CONSOLE_CORS_ALLOW_ORIGINS"); ok && hasStar(st.value) {
		c.add("DSA018", st, "CONSOLE_CORS_ALLOW_ORIGINS contains \"*\".")
	}
	if st, ok := c.get("api", "WEB_API_CORS_ALLOW_ORIGINS", "WEB_API_CORS_ALLOW_ORIGINS"); ok {
		if !st.set {
			c.add("DSA019", st, "WEB_API_CORS_ALLOW_ORIGINS is unset; the code default is \"*\".")
		} else if hasStar(st.value) {
			c.add("DSA019", st, "WEB_API_CORS_ALLOW_ORIGINS contains \"*\".")
		}
	}
}

// flag reports a boolean setting. def is the effective value when unset
// (compose fallback or code default); bad is the value that triggers.
func (c *ctx) flag(id, service, containerKey, envKey, def string, bad bool) {
	st, ok := c.get(service, containerKey, envKey)
	if !ok {
		return
	}
	v := st.value
	if !st.set {
		v = def
	}
	if truthy(v) == bad {
		shown := v
		if !st.set {
			shown = v + " (default)"
		}
		c.add(id, st, fmt.Sprintf("%s=%s", envKey, shown))
	}
}

func (c *ctx) ports() {
	for _, s := range c.in.Project.Services {
		if !c.active(s) {
			continue
		}
		for _, p := range s.Ports {
			if !p.AllInterfaces() {
				continue
			}
			st := setting{service: s.Name, file: c.in.Project.File, line: p.Line}
			pub := p.Published
			if pub == "" {
				pub = "(random)"
			}
			msg := fmt.Sprintf("%s publishes %s -> %s on all interfaces (\"%s\").", s.Name, pub, p.Target, p.Raw)
			switch s.Name {
			case "nginx":
				// The entry point is meant to be public; report for awareness.
				c.res.Findings = append(c.res.Findings, Finding{
					RuleID: "DSA101", Severity: Info, Title: "Entry point published on all host interfaces",
					Message: msg + " Expected for the public entry point; bind to 127.0.0.1 if another proxy sits in front.",
					Service: s.Name, File: st.file, Line: st.line,
				})
				continue
			case "plugin_daemon":
				msg += " This is the plugin remote-debugging (remote install) port; PLUGIN_REMOTE_INSTALLING_ENABLED defaults to true in plugin-daemon 0.6.10."
			}
			c.add("DSA101", st, msg)
		}
	}
}

func (c *ctx) privileged() {
	for _, s := range c.in.Project.Services {
		if c.active(s) && s.Privileged {
			c.add("DSA102", setting{service: s.Name, file: c.in.Project.File, line: s.PrivilegedLine}, s.Name+" has privileged: true.")
		}
	}
}

func (c *ctx) dockerSock() {
	for _, s := range c.in.Project.Services {
		if !c.active(s) {
			continue
		}
		for _, m := range s.Mounts {
			if strings.HasSuffix(m.Source, "docker.sock") {
				c.add("DSA103", setting{service: s.Name, file: c.in.Project.File, line: m.Line}, fmt.Sprintf("%s mounts %s.", s.Name, m.Source))
			}
		}
	}
}

func (c *ctx) hostNetwork() {
	for _, s := range c.in.Project.Services {
		if c.active(s) && s.NetworkMode == "host" {
			c.add("DSA104", setting{service: s.Name, file: c.in.Project.File, line: s.NetworkModeLine}, s.Name+" has network_mode: host.")
		}
	}
}

func (c *ctx) sandboxNetwork() {
	p := c.in.Project
	s := p.Service("sandbox")
	if s == nil || !c.active(s) {
		return
	}
	at := func(line int) setting { return setting{service: s.Name, file: p.File, line: line} }
	if s.NetworkMode != "" {
		c.add("DSA105", at(s.NetworkModeLine), fmt.Sprintf("sandbox uses network_mode: %s.", s.NetworkMode))
		return
	}
	if !s.NetworksDeclared {
		c.add("DSA105", at(s.Line), "sandbox declares no networks, so it joins the project's default network.")
		return
	}
	for _, n := range s.Networks {
		def, ok := p.Networks[n.Name]
		switch {
		case n.Name == "default":
			c.add("DSA105", at(n.Line), "sandbox is attached to the default network.")
		case !ok:
			c.add("DSA105", at(n.Line), fmt.Sprintf("sandbox network %q is not defined in this file, so it cannot be checked for internal: true.", n.Name))
		case def.External:
			c.add("DSA105", at(n.Line), fmt.Sprintf("sandbox network %q is external; check it is internal.", n.Name))
		case !def.Internal:
			c.add("DSA105", at(n.Line), fmt.Sprintf("sandbox network %q is not internal: true.", n.Name))
		}
	}
}
