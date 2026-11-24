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
	"strconv"
	"strings"
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
	PII_OFF        = "off"
	PII_MASK       = "«%s:%s»"
	PII_BYTES      = 6
	PII_FIELD      = "prompt_cache_key"
)

const (
	UPSTREAM_TIMEOUT = 5 * time.Minute
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
	key   string
	salt  string
	rules []rule
	pii   bool
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
		url:  upstream,
		key:  strings.TrimSpace(os.Getenv("OPENCODE_KEY")),
		salt: os.Getenv("PII_SALT"),
		pii:  strings.ToLower(strings.TrimSpace(os.Getenv("PII_MODE"))) != PII_OFF,
		max:  integer("MAX_BODY_SIZE", 1<<26),
		wait: seconds("UPSTREAM_TIMEOUT", UPSTREAM_TIMEOUT),
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
				res.Body = watch(res.Body, state, z.wait)
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

func authenticate(z *ocproxy, r *http.Request) {
	if z.key == "" {
		return
	}

	if bearer(r.Header.Get("Authorization")) != "" {
		return
	}

	if strings.TrimSpace(r.Header.Get("x-api-key")) != "" {
		return
	}

	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", z.key))
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
		{kind: "email", expr: `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`},
		{kind: "cpf", expr: `\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`, check: cpf},
		{kind: "cnpj", expr: `\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b`, check: cnpj},
		{kind: "card", expr: `\b\d{13,19}\b`, check: luhn},
		{kind: "card", expr: `\b\d{4}(?:[ -]\d{4}){2,4}\b`, check: luhn},
		{kind: "phone", expr: `(?:\+55[\s-]?(?:\d{2}[\s-]?)?9?\d{4}[\s-]?\d{4}|\(\d{2,3}\)[\s-]?9?\d{4}[\s-]?\d{4})`},
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

	return encode(scrub(body, z.rules, z.salt))
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

func scrub(value any, rules []rule, salt string) any {
	switch item := value.(type) {
	case map[string]any:
		for name, inner := range item {
			if name == PII_FIELD {
				continue
			}

			item[name] = scrub(inner, rules, salt)
		}

		return item
	case []any:
		for i, inner := range item {
			item[i] = scrub(inner, rules, salt)
		}

		return item
	case string:
		return shield(item, rules, salt)
	}

	return value
}

func shield(text string, rules []rule, salt string) string {
	for _, r := range rules {
		text = r.expr.ReplaceAllStringFunc(text, func(match string) string {
			if r.check != nil {
				if !r.check(match) {
					return match
				}
			}

			return stamp(r.kind, match, salt)
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
		authenticate(z, r)

		state := &state{key: key(r), start: time.Now()}
		r = r.WithContext(context.WithValue(r.Context(), tag{}, state))
		defer emit(state)

		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, z.max))
		if err != nil {
			fail(w, r, 413, fmt.Sprintf("Corpo excede o limite de %d bytes", z.max), err.Error())
			return
		}

		if z.pii {
			raw, err = redact(z, raw)
			if err != nil {
				fail(w, r, 500, "Erro interno", err.Error())
				return
			}
		}

		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.ContentLength = int64(len(raw))

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