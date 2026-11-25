package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

const (
	SESSION_HEADER = "x-opencode-session"
	ZEN_DEFAULT    = "https://opencode.ai/zen/go"
	ERROR_STATUS   = 400
	LOG_BODY_MAX   = 1 << 12
	UPGRADE_HEADER = "Upgrade"
	USAGE_LINE_MAX = 1 << 20
	KEY_BYTES      = 4
	NEWLINE        = "\n"
	DATA_MARKER    = "data:"
	USAGE_MARKER   = "usage"
	PII_MASK       = "«%s:%s»"
	PII_BYTES      = 6
	PII_FIELD      = "prompt_cache_key"
	STREAM_TYPE    = "text/event-stream"
	JSON_TYPE      = "application/json"
	DONE_MARKER    = "[DONE]"
	CHUNK_SIZE     = 1 << 14
	VAULT_LIMIT    = 4096
)

const (
	UPSTREAM_TIMEOUT = 90 * time.Second
	DIAL_TIMEOUT     = 10 * time.Second
	TLS_TIMEOUT      = 10 * time.Second
	HEADER_TIMEOUT   = 30 * time.Second
	IDLE_TIMEOUT     = 90 * time.Second
	POOL_SIZE        = 100
	KEEPALIVE        = 30 * time.Second
)

type ocproxy struct {
	url   *url.URL
	proxy *httputil.ReverseProxy
	salt  string
	rules []rule
	vault *vault
	max   int64
	wait  time.Duration
}

type reader struct {
	io.Reader
	io.Closer
}

type prompt struct {
	Model          string `json:"model"`
	PromptCacheKey string `json:"prompt_cache_key"`
}

type state struct {
	key     string
	model   string
	session string
	start   time.Time
	header  time.Time
	status  int
	usage   *usage
}

type usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	InputTokens      int `json:"input_tokens"`
	OutputTokens     int `json:"output_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type payload struct {
	Usage    usage `json:"usage"`
	Response struct {
		Usage usage `json:"usage"`
	} `json:"response"`
}

type spec struct {
	kind  string
	expr  string
	check func(string) bool
}

type rule struct {
	kind  string
	expr  *regexp.Regexp
	check func(string) bool
}

type vault struct {
	mu    sync.Mutex
	items map[string]string
}

type rewriter struct {
	inner io.ReadCloser
	vault *vault
	args  map[int]*strings.Builder
	carry []byte
	out   []byte
	in    []byte
	err   error
	done  bool
}

type stream struct {
	inner io.ReadCloser
	state *state
	carry []byte
	timer *time.Timer
	wait  time.Duration
}

type tag struct{}

type failure struct {
	Code    int    `json:"code"`
	Error   string `json:"error"`
	Details any    `json:"details"`
}

type health struct {
	Status string `json:"status"`
}

func new() (*ocproxy, error) {
	raw := cmp.Or(os.Getenv("ZEN_URL"), ZEN_DEFAULT)

	upstream, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("ZEN_URL invalida (%q): %w", raw, err)
	}

	if upstream.Scheme == "" {
		return nil, fmt.Errorf("ZEN_URL invalida (%q): esquema ausente", raw)
	}

	z := &ocproxy{
		url:   upstream,
		salt:  os.Getenv("PII_SALT"),
		vault: &vault{items: map[string]string{}},
		max:   integer("MAX_BODY_SIZE", 1<<26),
		wait:  seconds("UPSTREAM_TIMEOUT", UPSTREAM_TIMEOUT),
	}

	rules, err := patterns()
	if err != nil {
		return nil, err
	}

	z.rules = rules

	z.proxy = &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			strip(req.Out.Header)
			req.SetURL(upstream)
			req.SetXForwarded()
		},
		FlushInterval: -1,
		Transport:     transport(z.wait),
		ModifyResponse: func(res *http.Response) error {
			state := stateOf(res.Request.Context())
			state.header = time.Now()
			state.status = res.StatusCode

			if res.StatusCode < ERROR_STATUS {
				res.Body = watch(unwrap(res, z), state, z.wait)
				return nil
			}

			report(res)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			fail(w, r, 502, "Upstream falhou", err.Error())
		},
	}

	return z, nil
}

func strip(header http.Header) {
	upgrade := header.Get(UPGRADE_HEADER)
	if upgrade == "" {
		return
	}

	log.Printf("WARN: upgrade %q ignorado, upstream nao negocia protocolo", upgrade)

	header.Del("Connection")
	header.Del(UPGRADE_HEADER)
	header.Del("HTTP2-Settings")
	header.Del("Proxy-Connection")
	header.Del("Keep-Alive")
}

func seconds(name string, fallback time.Duration) time.Duration {
	return time.Duration(integer(name, int64(fallback/time.Second))) * time.Second
}

func transport(wait time.Duration) *http.Transport {
	dial := &net.Dialer{Timeout: DIAL_TIMEOUT, KeepAlive: KEEPALIVE}

	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dial.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          POOL_SIZE,
		MaxIdleConnsPerHost:   POOL_SIZE,
		IdleConnTimeout:       IDLE_TIMEOUT,
		TLSHandshakeTimeout:   TLS_TIMEOUT,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: wait,
	}
}

func integer(name string, fallback int64) int64 {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}

	v, err := strconv.ParseInt(raw, 10, 64)
	if err == nil {
		if v > 0 {
			return v
		}
	}

	log.Printf("WARN: %s invalida (%q), usando %d", name, raw, fallback)
	return fallback
}

func body(raw []byte) prompt {
	p := &prompt{}
	if err := json.Unmarshal(raw, p); err != nil {
		return prompt{}
	}

	return *p
}

func stateOf(ctx context.Context) *state {
	s, ok := ctx.Value(tag{}).(*state)
	if ok {
		return s
	}

	return &state{}
}

func model(p prompt) string {
	return cmp.Or(p.Model, "-")
}

func bearer(header string) string {
	prefix := "Bearer "

	if !strings.HasPrefix(header, prefix) {
		return ""
	}

	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func key(r *http.Request) string {
	raw := cmp.Or(bearer(r.Header.Get("Authorization")), strings.TrimSpace(r.Header.Get("x-api-key")))

	if raw == "" {
		return "-"
	}

	sum := sha256.Sum256([]byte(raw))

	return hex.EncodeToString(sum[:KEY_BYTES])
}

func patterns() ([]rule, error) {
	specs := []spec{
		{kind: "ssh", expr: `(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`},
		{kind: "gpg", expr: `(?s)-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----`},
		{kind: "putty", expr: `(?s)PuTTY-User-Key-File-\d+:.*?Private-MAC:\s*[0-9a-fA-F]+`},
		{kind: "dsn", expr: `(?i)\b(?:postgres|postgresql|mysql|mariadb|mongodb|mongodb\+srv|redis|rediss|amqp|amqps|sqlserver|mssql|clickhouse)://[^\s:@/]*:[^\s@/]*@[^\s"'<>\\)]+`},
		{kind: "jwt", expr: `\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`},
		{kind: "bearer", expr: `(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{16,}`},
		{kind: "basic", expr: `(?i)\bbasic\s+[A-Za-z0-9+/=]{16,}`},
		{kind: "openai", expr: `\bsk-(?:ant-)?[A-Za-z0-9_\-]{20,}`},
		{kind: "stripe", expr: `\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}`},
		{kind: "google", expr: `\bAIza[0-9A-Za-z_\-]{35}`},
		{kind: "slack", expr: `\bxox[baprs]-[A-Za-z0-9\-]{10,}`},
		{kind: "npm", expr: `\bnpm_[A-Za-z0-9]{36}`},
		{kind: "sendgrid", expr: `\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}`},
		{kind: "huggingface", expr: `\bhf_[A-Za-z0-9]{30,}`},
		{kind: "sentry", expr: `https://[0-9a-f]{16,}@[A-Za-z0-9.\-]*ingest\.sentry\.io/\d+`},
		{kind: "aws", expr: `(?i)aws_?(?:secret_?access_?key|access_?key_?id|session_?token)\s*[=:]\s*["']?[A-Za-z0-9/+=]{16,}`},
		{kind: "aws", expr: `\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b`},
		{kind: "github", expr: `\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})`},
		{kind: "gitlab", expr: `\bgl(?:pat|rt|dt|cbt|ptt|soat|imt|ffct|oas|agent)-[A-Za-z0-9_.\-]{20,}`},
		{kind: "cpf", expr: `\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`, check: cpf},
		{kind: "cpf", expr: `\b\d{11}\b`, check: cpf},
		{kind: "cnpj", expr: `\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b`, check: cnpj},
		{kind: "cnpj", expr: `\b\d{14}\b`, check: cnpj},
		{kind: "email", expr: `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`},
		{kind: "card", expr: `\b\d{13,19}\b`, check: luhn},
		{kind: "card", expr: `\b\d{4}(?:[ -]\d{4}){2,4}\b`, check: luhn},
		{kind: "phone", expr: `(?:\+55[\s-]?(?:\d{2}[\s-]?)?9?\d{4}[\s-]?\d{4}|\(\d{2,3}\)[\s-]?9?\d{4}[\s-]?\d{4})`},
		{kind: "secret", expr: `(?i)(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|client[_\-]?secret|auth[_\-]?token|credential)s?\b["']?\s*[=:]\s*["']?[^\s"',;]{8,}`},
	}

	rules := make([]rule, 0, len(specs))

	for _, item := range specs {
		expr, err := regexp.Compile(item.expr)
		if err != nil {
			return nil, fmt.Errorf("pii %s: %w", item.kind, err)
		}

		rules = append(rules, rule{kind: item.kind, expr: expr, check: item.check})
	}

	return rules, nil
}

func redact(z *ocproxy, raw []byte) ([]byte, error) {
	if !json.Valid(raw) {
		return raw, nil
	}

	body := any(nil)

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	if err := dec.Decode(&body); err != nil {
		return nil, fmt.Errorf("pii: %w", err)
	}

	return encode(scrub(body, z.rules, z.salt, z.vault))
}

func encode(body any) ([]byte, error) {
	buf := &bytes.Buffer{}

	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(body); err != nil {
		return nil, fmt.Errorf("pii: %w", err)
	}

	return bytes.TrimSuffix(buf.Bytes(), []byte(NEWLINE)), nil
}

func scrub(value any, rules []rule, salt string, v *vault) any {
	switch item := value.(type) {
	case map[string]any:
		for name, inner := range item {
			if name == PII_FIELD {
				continue
			}

			item[name] = scrub(inner, rules, salt, v)
		}

		return item
	case []any:
		for i, inner := range item {
			item[i] = scrub(inner, rules, salt, v)
		}

		return item
	case string:
		return shield(item, rules, salt, v)
	}

	return value
}

func shield(text string, rules []rule, salt string, v *vault) string {
	for _, r := range rules {
		text = r.expr.ReplaceAllStringFunc(text, func(match string) string {
			if r.check != nil {
				if !r.check(match) {
					return match
				}
			}

			mask := stamp(r.kind, match, salt)
			v.keep(mask, match)

			return mask
		})
	}

	return text
}

func stamp(kind string, value string, salt string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", salt, value)))

	return fmt.Sprintf(PII_MASK, kind, hex.EncodeToString(sum[:PII_BYTES]))
}

func digits(raw string) string {
	out := make([]rune, 0, len(raw))

	for _, c := range raw {
		if c < '0' {
			continue
		}

		if c > '9' {
			continue
		}

		out = append(out, c)
	}

	return string(out)
}

func verify(raw string, weights []int) bool {
	sum := 0

	for i, w := range weights {
		sum += int(raw[i]-'0') * w
	}

	mod := sum % 11
	digit := 0

	if mod >= 2 {
		digit = 11 - mod
	}

	return digit == int(raw[len(weights)]-'0')
}

func cpf(value string) bool {
	raw := digits(value)

	if len(raw) != 11 {
		return false
	}

	if !verify(raw, []int{10, 9, 8, 7, 6, 5, 4, 3, 2}) {
		return false
	}

	return verify(raw, []int{11, 10, 9, 8, 7, 6, 5, 4, 3, 2})
}

func cnpj(value string) bool {
	raw := digits(value)

	if len(raw) != 14 {
		return false
	}

	if !verify(raw, []int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}) {
		return false
	}

	return verify(raw, []int{6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2})
}

func luhn(value string) bool {
	raw := digits(value)

	if len(raw) < 13 {
		return false
	}

	if len(raw) > 19 {
		return false
	}

	sum := 0
	double := false

	for i := len(raw) - 1; i >= 0; i-- {
		digit := int(raw[i] - '0')

		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}

		sum += digit
		double = !double
	}

	return sum%10 == 0
}

func tokens(line []byte) (usage, bool) {
	raw := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(line), []byte(DATA_MARKER)))

	p := &payload{}
	if err := json.Unmarshal(raw, p); err != nil {
		return usage{}, false
	}

	if p.Usage != (usage{}) {
		return p.Usage, true
	}

	if p.Response.Usage != (usage{}) {
		return p.Response.Usage, true
	}

	return usage{}, false
}

func in(item *usage) string {
	if item == nil {
		return "-"
	}

	return strconv.Itoa(cmp.Or(item.PromptTokens, item.InputTokens))
}

func out(item *usage) string {
	if item == nil {
		return "-"
	}

	return strconv.Itoa(cmp.Or(item.CompletionTokens, item.OutputTokens))
}

func watch(inner io.ReadCloser, state *state, wait time.Duration) *stream {
	u := &stream{inner: inner, state: state, wait: wait}
	u.timer = time.AfterFunc(wait, func() { abort(u) })

	return u
}

func abort(u *stream) {
	log.Printf("WARN: sessao %s sem dados por %s, abortando", u.state.session, u.wait)

	if err := u.inner.Close(); err != nil {
		log.Printf("ERROR: sessao %s: %s", u.state.session, err.Error())
	}
}

func (u *stream) Read(p []byte) (int, error) {
	u.timer.Reset(u.wait)

	n, err := u.inner.Read(p)
	if n > 0 {
		u.scan(p[:n])
	}

	return n, err
}

func (u *stream) Close() error {
	u.timer.Stop()

	return u.inner.Close()
}

func (u *stream) scan(chunk []byte) {
	lines := bytes.Split(append(u.carry, chunk...), []byte(NEWLINE))

	u.carry = append([]byte(nil), lines[len(lines)-1]...)
	if len(u.carry) > USAGE_LINE_MAX {
		u.carry = u.carry[len(u.carry)-USAGE_LINE_MAX:]
	}

	for _, line := range lines[:len(lines)-1] {
		u.parse(line)
	}
}

func (u *stream) parse(line []byte) {
	if bytes.Contains(line, []byte(USAGE_MARKER)) {
		if value, ok := tokens(line); ok {
			u.state.usage = &value
		}
	}
}

func generate() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("gerar sessao: %w", err)
	}

	return strconv.FormatUint(binary.BigEndian.Uint64(raw), 10), nil
}

func report(res *http.Response) {
	state := stateOf(res.Request.Context())

	raw, err := io.ReadAll(io.LimitReader(res.Body, LOG_BODY_MAX))
	if err != nil {
		log.Printf("ERROR: %d upstream key=%s model=%s %s: %s", res.StatusCode, state.key, state.model, res.Request.URL.Path, err.Error())
		return
	}

	res.Body = reader{
		Reader: io.MultiReader(bytes.NewReader(raw), res.Body),
		Closer: res.Body,
	}

	log.Printf("ERROR: %d upstream key=%s model=%s %s %s: %s", res.StatusCode, state.key, state.model, res.Request.Method, res.Request.URL.Path, collapse(raw))
}

func collapse(raw []byte) string {
	return strings.Join(strings.Fields(string(raw)), " ")
}

func emit(state *state) {
	log.Printf("SESSION %s key=%s model=%s status=%d in=%s out=%s ttfb=%s total=%s", state.session, state.key, state.model, state.status, in(state.usage), out(state.usage), ttfb(state), time.Since(state.start).Round(time.Millisecond))
}

func ttfb(state *state) string {
	if state.header.IsZero() {
		return "-"
	}

	return state.header.Sub(state.start).Round(time.Millisecond).String()
}

func forward(z *ocproxy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := &state{key: key(r), start: time.Now()}
		r = r.WithContext(context.WithValue(r.Context(), tag{}, state))
		defer emit(state)

		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, z.max))
		if err != nil {
			fail(w, r, 413, fmt.Sprintf("Corpo excede o limite de %d bytes", z.max), err.Error())
			return
		}

		p := body(raw)
		state.model = model(p)

		session := p.PromptCacheKey
		if session == "" {
			session, err = generate()
			if err != nil {
				fail(w, r, 500, "Erro interno", err.Error())
				return
			}
		}

		state.session = session

		raw, err = redact(z, raw)
		if err != nil {
			fail(w, r, 500, "Erro interno", err.Error())
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.ContentLength = int64(len(raw))
		r.Header.Set(SESSION_HEADER, session)

		z.proxy.ServeHTTP(w, r)
	}
}

func healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		write(w, http.StatusOK, health{Status: "ok"})
	}
}

func fail(w http.ResponseWriter, r *http.Request, code int, message string, details any) {
	state := stateOf(r.Context())
	state.status = code

	log.Printf("ERROR: %d key=%s model=%s %s %s: %s (%v)", code, state.key, state.model, r.Method, r.URL.Path, message, details)
	write(w, code, failure{Code: code, Error: message, Details: details})
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(body); err != nil {
		log.Printf("ERROR: resposta %d: %s", status, err.Error())
	}
}

func main() {
	z, err := new()
	if err != nil {
		log.Fatal(err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "9093"
	}

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Get("/healthz", healthz())
	r.Handle("/*", forward(z))

	s := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           r,
		ReadHeaderTimeout: HEADER_TIMEOUT,
		IdleTimeout:       IDLE_TIMEOUT,
	}

	log.Printf("LISTENING %s -> %s", port, z.url)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func unwrap(res *http.Response, z *ocproxy) io.ReadCloser {
	kind := res.Header.Get("Content-Type")

	if strings.Contains(kind, STREAM_TYPE) {
		return &rewriter{inner: res.Body, vault: z.vault, args: map[int]*strings.Builder{}, in: make([]byte, CHUNK_SIZE)}
	}

	if !strings.Contains(kind, JSON_TYPE) {
		return res.Body
	}

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return reader{Reader: bytes.NewReader(raw), Closer: res.Body}
	}

	return io.NopCloser(bytes.NewReader(restore(raw, z.vault)))
}

func restore(raw []byte, v *vault) []byte {
	value, err := decode(raw)
	if err != nil {
		return raw
	}

	unmask(value, v)

	out, err := encode(value)
	if err != nil {
		return raw
	}

	return out
}

func decode(raw []byte) (any, error) {
	value := any(nil)

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("pii: %w", err)
	}

	return value, nil
}

func unmask(value any, v *vault) {
	switch item := value.(type) {
	case map[string]any:
		if list, ok := item["tool_calls"]; ok {
			calls(list, v)
		}

		if call, ok := item["function_call"]; ok {
			args(call, v)
		}

		for _, inner := range item {
			unmask(inner, v)
		}
	case []any:
		for _, inner := range item {
			unmask(inner, v)
		}
	}
}

func calls(value any, v *vault) {
	list, ok := value.([]any)
	if !ok {
		return
	}

	for _, entry := range list {
		args(entry, v)
	}
}

func args(value any, v *vault) {
	item, ok := value.(map[string]any)
	if !ok {
		return
	}

	target := item

	if fn, ok := item["function"].(map[string]any); ok {
		target = fn
	}

	text, ok := target["arguments"].(string)
	if !ok {
		return
	}

	target["arguments"] = v.open(text)
}

func quote(text string) string {
	raw, err := json.Marshal(text)
	if err != nil {
		return `""`
	}

	return string(raw)
}

func number(value any) int {
	switch item := value.(type) {
	case json.Number:
		slot, err := item.Int64()
		if err != nil {
			return 0
		}

		return int(slot)
	case float64:
		return int(item)
	}

	return 0
}

func (v *vault) keep(mask string, value string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if len(v.items) >= VAULT_LIMIT {
		return
	}

	v.items[mask] = value
}

func (v *vault) open(text string) string {
	v.mu.Lock()
	defer v.mu.Unlock()

	if len(v.items) == 0 {
		return text
	}

	pairs := make([]string, 0, len(v.items)*2)

	for mask, value := range v.items {
		pairs = append(pairs, mask, value)
	}

	return strings.NewReplacer(pairs...).Replace(text)
}

func (w *rewriter) Read(p []byte) (int, error) {
	for len(w.out) == 0 {
		if w.done {
			return 0, w.err
		}

		n, err := w.inner.Read(w.in)
		if n > 0 {
			w.scan(w.in[:n])
		}

		if err != nil {
			w.err = err
			w.finish()
		}
	}

	n := copy(p, w.out)
	w.out = w.out[n:]

	return n, nil
}

func (w *rewriter) Close() error {
	return w.inner.Close()
}

func (w *rewriter) scan(chunk []byte) {
	w.carry = append(w.carry, chunk...)

	for {
		i := bytes.IndexByte(w.carry, '\n')
		if i < 0 {
			return
		}

		line := w.carry[:i]
		w.carry = w.carry[i+1:]

		w.line(line)
	}
}

func (w *rewriter) line(raw []byte) {
	text := strings.TrimSpace(string(raw))

	if !strings.HasPrefix(text, DATA_MARKER) {
		w.write(string(raw))
		return
	}

	payload := strings.TrimSpace(strings.TrimPrefix(text, DATA_MARKER))
	if payload == DONE_MARKER {
		w.flush()
		w.write(string(raw))
		return
	}

	w.patch(payload, string(raw))
}

func (w *rewriter) patch(payload string, raw string) {
	value, err := decode([]byte(payload))
	if err != nil {
		w.write(raw)
		return
	}

	body, ok := value.(map[string]any)
	if !ok {
		w.write(raw)
		return
	}

	list, ok := body["choices"].([]any)
	if !ok {
		w.write(raw)
		return
	}

	end := false

	for _, entry := range list {
		choice, ok := entry.(map[string]any)
		if !ok {
			continue
		}

		if _, ok := choice["finish_reason"].(string); ok {
			end = true
		}

		delta, ok := choice["delta"].(map[string]any)
		if !ok {
			continue
		}

		items, ok := delta["tool_calls"].([]any)
		if !ok {
			continue
		}

		w.collect(items)
	}

	if end {
		w.flush()
	}

	out, err := encode(body)
	if err != nil {
		w.write(raw)
		return
	}

	w.write(fmt.Sprintf("%s %s", DATA_MARKER, out))
}

func (w *rewriter) collect(items []any) {
	for _, entry := range items {
		call, ok := entry.(map[string]any)
		if !ok {
			continue
		}

		fn, ok := call["function"].(map[string]any)
		if !ok {
			continue
		}

		text, ok := fn["arguments"].(string)
		if !ok {
			continue
		}

		if text == "" {
			continue
		}

		w.keep(call["index"], text)
		fn["arguments"] = ""
	}
}

func (w *rewriter) keep(index any, text string) {
	slot := number(index)

	builder, ok := w.args[slot]
	if !ok {
		builder = &strings.Builder{}
		w.args[slot] = builder
	}

	builder.WriteString(text)
}

func (w *rewriter) flush() {
	if len(w.args) == 0 {
		return
	}

	slots := make([]int, 0, len(w.args))

	for slot := range w.args {
		slots = append(slots, slot)
	}

	sort.Ints(slots)

	for _, slot := range slots {
		text := w.vault.open(w.args[slot].String())
		chunk := fmt.Sprintf(`{"choices":[{"index":%d,"delta":{"tool_calls":[{"index":%d,"function":{"arguments":%s}}]},"finish_reason":null}]}`, slot, slot, quote(text))

		w.write(fmt.Sprintf("%s %s", DATA_MARKER, chunk))
	}

	w.args = map[int]*strings.Builder{}
}

func (w *rewriter) write(line string) {
	w.out = append(w.out, line...)
	w.out = append(w.out, NEWLINE...)
}

func (w *rewriter) finish() {
	if len(w.carry) != 0 {
		w.line(w.carry)
		w.carry = nil
	}

	w.flush()

	w.done = true
}