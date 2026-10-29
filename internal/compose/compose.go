// Package compose reads the parts of a Docker Compose file that matter for
// this audit: services, profiles, ports, privileges, mounts, networks and the
// environment each container ends up with. It never runs Docker.
package compose

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/OTA-EITA/dify-selfhost-audit/internal/envfile"
	"github.com/OTA-EITA/dify-selfhost-audit/internal/interp"
)

// Value is a resolved setting together with the place that decided it.
type Value struct {
	Value string
	File  string
	Line  int
	// Origin explains the source, e.g. "env_file", "environment",
	// "compose default".
	Origin string
}

// Port is one entry of a service's ports list.
type Port struct {
	Raw       string
	HostIP    string
	Published string
	Target    string
	Protocol  string
	Line      int
}

// AllInterfaces reports whether the port is published on every host
// interface (no host IP, 0.0.0.0 or ::).
func (p Port) AllInterfaces() bool {
	switch strings.Trim(p.HostIP, "[]") {
	case "", "0.0.0.0", "::":
		return true
	}
	return false
}

// Mount is one entry of a service's volumes list.
type Mount struct {
	Raw    string
	Source string
	Target string
	Line   int
}

// NetRef is a network a service is attached to.
type NetRef struct {
	Name string
	Line int
}

// Service is a compose service.
type Service struct {
	Name            string
	Line            int
	Image           string
	Profiles        []string
	Ports           []Port
	Privileged      bool
	PrivilegedLine  int
	NetworkMode     string
	NetworkModeLine int
	Mounts          []Mount
	Networks        []NetRef
	// NetworksDeclared is false when the service has no networks key and
	// therefore joins the project's default network.
	NetworksDeclared bool
	// Env is the environment the container receives: env_file entries in
	// order, then the environment key.
	Env map[string]Value
}

// Active reports whether the service starts with the given profiles.
func (s *Service) Active(profiles map[string]bool) bool {
	if len(s.Profiles) == 0 {
		return true
	}
	if profiles["*"] {
		return true
	}
	for _, p := range s.Profiles {
		if profiles[p] {
			return true
		}
	}
	return false
}

// Network is a top-level network definition.
type Network struct {
	Name     string
	Internal bool
	External bool
	Line     int
}

// Project is a parsed compose file.
type Project struct {
	File     string
	Dir      string
	Services []*Service
	Networks map[string]*Network
	// Profiles is the set named by COMPOSE_PROFILES.
	Profiles map[string]bool
	// Notes are non-fatal remarks made while loading.
	Notes []string
}

// Service returns the named service or nil.
func (p *Project) Service(name string) *Service {
	for _, s := range p.Services {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// Load parses the compose file at path. projectEnv supplies the variables
// used for interpolation (what Compose reads from .env / --env-file); the
// shell environment is deliberately ignored so results are reproducible.
func Load(path string, projectEnv *envfile.Env) (*Project, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("%s: empty document", path)
	}
	root := deref(doc.Content[0])
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: top level is not a mapping", path)
	}
	if projectEnv == nil {
		projectEnv = envfile.New()
	}
	l := &loader{file: path, dir: filepath.Dir(path), env: projectEnv}
	p := &Project{File: path, Dir: l.dir, Networks: map[string]*Network{}, Profiles: map[string]bool{}}

	if v, ok := projectEnv.Lookup("COMPOSE_PROFILES"); ok {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				p.Profiles[s] = true
			}
		}
	}

	if n := get(root, "networks"); n != nil {
		for _, kv := range pairs(n) {
			nw := &Network{Name: kv.key.Value, Line: kv.key.Line}
			if kv.val.Kind == yaml.MappingNode {
				if b := get(kv.val, "internal"); b != nil {
					nw.Internal = l.truthy(b)
				}
				if b := get(kv.val, "external"); b != nil {
					nw.External = b.Kind == yaml.MappingNode || l.truthy(b)
				}
			}
			p.Networks[nw.Name] = nw
		}
	}

	svcs := get(root, "services")
	if svcs == nil {
		return nil, fmt.Errorf("%s: no services", path)
	}
	for _, kv := range pairs(svcs) {
		s, err := l.service(kv.key, kv.val)
		if err != nil {
			return nil, err
		}
		p.Services = append(p.Services, s)
	}
	p.Notes = l.notes
	return p, nil
}

type loader struct {
	file  string
	dir   string
	env   *envfile.Env
	notes []string
	noted map[string]bool
}

func (l *loader) note(s string) {
	if l.noted == nil {
		l.noted = map[string]bool{}
	}
	if !l.noted[s] {
		l.noted[s] = true
		l.notes = append(l.notes, s)
	}
}

func (l *loader) str(n *yaml.Node) string {
	n = deref(n)
	if n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return ""
	}
	v, _, err := interp.Interpolate(n.Value, l.env.Lookup)
	if err != nil {
		l.note(fmt.Sprintf("%s:%d: %v", l.file, n.Line, err))
		return n.Value
	}
	return v
}

func (l *loader) truthy(n *yaml.Node) bool {
	switch strings.ToLower(strings.TrimSpace(l.str(n))) {
	case "true", "yes", "on", "1":
		return true
	}
	return false
}

func (l *loader) service(key, n *yaml.Node) (*Service, error) {
	s := &Service{Name: key.Value, Line: key.Line, Env: map[string]Value{}}
	if n.Kind != yaml.MappingNode {
		return s, nil
	}
	for _, kv := range pairs(n) {
		v := kv.val
		switch kv.key.Value {
		case "image":
			s.Image = l.str(v)
		case "profiles":
			for _, it := range seq(v) {
				s.Profiles = append(s.Profiles, l.str(it))
			}
		case "privileged":
			s.Privileged = l.truthy(v)
			s.PrivilegedLine = kv.key.Line
		case "network_mode":
			s.NetworkMode = l.str(v)
			s.NetworkModeLine = kv.key.Line
		case "ports":
			for _, it := range seq(v) {
				s.Ports = append(s.Ports, l.port(it))
			}
		case "volumes":
			for _, it := range seq(v) {
				s.Mounts = append(s.Mounts, l.mount(it))
			}
		case "networks":
			s.NetworksDeclared = true
			v = deref(v)
			if v.Kind == yaml.SequenceNode {
				for _, it := range seq(v) {
					s.Networks = append(s.Networks, NetRef{Name: l.str(it), Line: it.Line})
				}
			} else if v.Kind == yaml.MappingNode {
				for _, p := range pairs(v) {
					s.Networks = append(s.Networks, NetRef{Name: p.key.Value, Line: p.key.Line})
				}
			}
		}
	}
	// env_file first, then environment overrides it.
	if v := get(n, "env_file"); v != nil {
		if err := l.envFiles(s, v); err != nil {
			return nil, err
		}
	}
	if v := get(n, "environment"); v != nil {
		l.environment(s, v)
	}
	return s, nil
}

func (l *loader) envFiles(s *Service, n *yaml.Node) error {
	n = deref(n)
	var items []*yaml.Node
	if n.Kind == yaml.ScalarNode {
		items = []*yaml.Node{n}
	} else {
		items = seq(n)
	}
	for _, it := range items {
		it = deref(it)
		var p string
		required := true
		if it.Kind == yaml.MappingNode {
			if pv := get(it, "path"); pv != nil {
				p = l.str(pv)
			}
			if rv := get(it, "required"); rv != nil {
				required = l.truthy(rv)
			}
		} else {
			p = l.str(it)
		}
		if p == "" {
			continue
		}
		full := p
		if !filepath.IsAbs(full) {
			full = filepath.Join(l.dir, p)
		}
		env, err := envfile.ParseFile(full, l.env)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if !required {
				continue
			}
			if filepath.Base(p) == ".env" && len(l.env.Keys()) > 0 {
				// Auditing .env.example without copying it to .env: the
				// files given with --env stand in for the missing .env.
				l.note(fmt.Sprintf("%s not found; using the --env file(s) in its place for env_file", p))
				env = l.env
			} else {
				l.note(fmt.Sprintf("service %s: env_file %s not found (Compose would refuse to start)", s.Name, p))
				continue
			}
		}
		for _, k := range env.Keys() {
			e, _ := env.Get(k)
			s.Env[k] = Value{Value: e.Value, File: e.File, Line: e.Line, Origin: "env_file"}
		}
	}
	return nil
}

func (l *loader) environment(s *Service, n *yaml.Node) {
	n = deref(n)
	set := func(key string, raw *yaml.Node, rawValue string, line int) {
		v, uses, err := interp.Interpolate(rawValue, l.env.Lookup)
		if err != nil {
			l.note(fmt.Sprintf("%s:%d: %v", l.file, line, err))
			v = rawValue
		}
		val := Value{Value: v, File: l.file, Line: line, Origin: "environment"}
		if len(uses) > 0 {
			u := uses[0]
			if u.Fallback {
				val.Origin = "compose default"
			} else if u.Set {
				if e, ok := l.env.Get(u.Name); ok {
					val.File, val.Line = e.File, e.Line
					val.Origin = "environment via " + u.Name
				}
			}
		}
		s.Env[key] = val
	}
	switch n.Kind {
	case yaml.MappingNode:
		for _, kv := range pairs(n) {
			vn := deref(kv.val)
			if vn.Kind != yaml.ScalarNode || vn.Tag == "!!null" {
				continue // value comes from the shell; ignored
			}
			set(kv.key.Value, vn, vn.Value, kv.key.Line)
		}
	case yaml.SequenceNode:
		for _, it := range seq(n) {
			it = deref(it)
			k, v, ok := strings.Cut(it.Value, "=")
			if !ok {
				continue
			}
			set(k, it, v, it.Line)
		}
	}
}

func (l *loader) port(n *yaml.Node) Port {
	n = deref(n)
	p := Port{Line: n.Line}
	if n.Kind == yaml.MappingNode {
		for _, kv := range pairs(n) {
			switch kv.key.Value {
			case "target":
				p.Target = l.str(kv.val)
			case "published":
				p.Published = l.str(kv.val)
			case "host_ip":
				p.HostIP = l.str(kv.val)
			case "protocol":
				p.Protocol = l.str(kv.val)
			}
		}
		p.Raw = fmt.Sprintf("%s:%s:%s", p.HostIP, p.Published, p.Target)
		return p
	}
	p.Raw = l.str(n)
	return ParsePort(p.Raw, p.Line)
}

// ParsePort parses the short port syntax [HOST_IP:][HOST_PORT:]CONTAINER_PORT[/PROTO].
func ParsePort(raw string, line int) Port {
	p := Port{Raw: raw, Line: line}
	s := raw
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		p.Protocol = s[i+1:]
		s = s[:i]
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]:"); end > 0 {
			p.HostIP = s[:end+1]
			s = s[end+2:]
			if pub, tgt, ok := strings.Cut(s, ":"); ok {
				p.Published, p.Target = pub, tgt
			} else {
				p.Target = s
			}
			return p
		}
	}
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 1:
		p.Target = parts[0]
	case 2:
		p.Published, p.Target = parts[0], parts[1]
	default:
		p.HostIP = strings.Join(parts[:len(parts)-2], ":")
		p.Published, p.Target = parts[len(parts)-2], parts[len(parts)-1]
	}
	return p
}

func (l *loader) mount(n *yaml.Node) Mount {
	n = deref(n)
	m := Mount{Line: n.Line}
	if n.Kind == yaml.MappingNode {
		if v := get(n, "source"); v != nil {
			m.Source = l.str(v)
		}
		if v := get(n, "target"); v != nil {
			m.Target = l.str(v)
		}
		m.Raw = m.Source + ":" + m.Target
		return m
	}
	m.Raw = l.str(n)
	parts := strings.Split(m.Raw, ":")
	if len(parts) >= 2 {
		m.Source, m.Target = parts[0], parts[1]
	} else {
		m.Target = parts[0]
	}
	return m
}

// --- yaml.Node helpers with anchor/alias and merge-key (<<) support ---

type pair struct{ key, val *yaml.Node }

func deref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func seq(n *yaml.Node) []*yaml.Node {
	n = deref(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

// pairs returns a mapping's entries with merge keys applied: explicit keys
// win over merged ones, and the order is merged keys first, then explicit.
func pairs(n *yaml.Node) []pair {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	var explicit []pair
	var merged []pair
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Value == "<<" && (k.Tag == "!!merge" || k.Tag == "") {
			src := deref(v)
			var maps []*yaml.Node
			if src.Kind == yaml.SequenceNode {
				maps = src.Content
			} else {
				maps = []*yaml.Node{src}
			}
			for _, m := range maps {
				for _, p := range pairs(m) {
					if !hasKey(merged, p.key.Value) {
						merged = append(merged, p)
					}
				}
			}
			continue
		}
		explicit = append(explicit, pair{k, v})
	}
	out := make([]pair, 0, len(merged)+len(explicit))
	for _, p := range merged {
		if !hasKey(explicit, p.key.Value) {
			out = append(out, p)
		}
	}
	return append(out, explicit...)
}

func hasKey(ps []pair, k string) bool {
	for _, p := range ps {
		if p.key.Value == k {
			return true
		}
	}
	return false
}

func get(n *yaml.Node, key string) *yaml.Node {
	for _, p := range pairs(n) {
		if p.key.Value == key {
			return p.val
		}
	}
	return nil
}

// SortedProfiles returns the active profile names, sorted.
func (p *Project) SortedProfiles() []string {
	var out []string
	for k := range p.Profiles {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
