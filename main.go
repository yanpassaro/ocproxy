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
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
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
)

type zenProxy struct {
	url   *url.URL
	proxy *httputil.ReverseProxy
	max   int64
}

type readCloser struct {
	io.Reader
	io.Closer
}

type promptBody struct {
	Model          string `json:"model"`
	PromptCacheKey string `json:"prompt_cache_key"`
}

type requestState struct {
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

type usageBody struct {
	Usage    usage `json:"usage"`
	Response struct {
		Usage usage `json:"usage"`
	} `json:"response"`
}

type usageReader struct {
	inner io.ReadCloser
	state *requestState
	carry []byte
}

type stateKey struct{}

type errorResponse struct {
	Code    int    `json:"code"`
	Error   string `json:"error"`
	Details any    `json:"details"`
}

type healthResponse struct {
	Status string `json:"status"`
}

func new() (*zenProxy, error) {
	raw := cmp.Or(os.Getenv("ZEN_URL"), ZEN_DEFAULT)

	upstream, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("ZEN_URL invalida (%q): %w", raw, err)
	}

	if upstream.Scheme == "" {
		return nil, fmt.Errorf("ZEN_URL invalida (%q): esquema ausente", raw)
	}

	z := &zenProxy{
		url: upstream,
		max: integer("MAX_BODY_SIZE", 1<<26),
	}

	z.proxy = &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			stripUpgrade(req.Out.Header)
			req.SetURL(upstream)
			req.SetXForwarded()
		},
		FlushInterval: -1,
		ModifyResponse: func(res *http.Response) error {
			state := stateOf(res.Request.Context())
			state.header = time.Now()
			state.status = res.StatusCode

			if res.StatusCode < ERROR_STATUS {
				res.Body = &usageReader{inner: res.Body, state: state}
				return nil
			}

			logUpstream(res)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			fail(w, r, 502, "Upstream falhou", err.Error())
		},
	}

	return z, nil
}

func stripUpgrade(header http.Header) {
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

func prompt(raw []byte) promptBody {
	body := &promptBody{}
	if err := json.Unmarshal(raw, body); err != nil {
		return promptBody{}
	}

	return *body
}

func stateOf(ctx context.Context) *requestState {
	state, ok := ctx.Value(stateKey{}).(*requestState)
	if ok {
		return state
	}

	return &requestState{}
}

func model(prompt promptBody) string {
	return cmp.Or(prompt.Model, "-")
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

func usageOf(line []byte) (usage, bool) {
	raw := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(line), []byte(DATA_MARKER)))

	body := &usageBody{}
	if err := json.Unmarshal(raw, body); err != nil {
		return usage{}, false
	}

	if body.Usage != (usage{}) {
		return body.Usage, true
	}

	if body.Response.Usage != (usage{}) {
		return body.Response.Usage, true
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

func (u *usageReader) Read(p []byte) (int, error) {
	n, err := u.inner.Read(p)
	if n > 0 {
		u.scan(p[:n])
	}

	return n, err
}

func (u *usageReader) Close() error {
	return u.inner.Close()
}

func (u *usageReader) scan(chunk []byte) {
	lines := bytes.Split(append(u.carry, chunk...), []byte(NEWLINE))

	u.carry = append([]byte(nil), lines[len(lines)-1]...)
	if len(u.carry) > USAGE_LINE_MAX {
		u.carry = u.carry[len(u.carry)-USAGE_LINE_MAX:]
	}

	for _, line := range lines[:len(lines)-1] {
		u.parse(line)
	}
}

func (u *usageReader) parse(line []byte) {
	if bytes.Contains(line, []byte(USAGE_MARKER)) {
		if value, ok := usageOf(line); ok {
			u.state.usage = &value
		}
	}
}

func randomSession() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("gerar sessao: %w", err)
	}

	return strconv.FormatUint(binary.BigEndian.Uint64(raw), 10), nil
}

func logUpstream(res *http.Response) {
	state := stateOf(res.Request.Context())

	body, err := io.ReadAll(io.LimitReader(res.Body, LOG_BODY_MAX))
	if err != nil {
		log.Printf("ERROR: %d upstream key=%s model=%s %s: %s", res.StatusCode, state.key, state.model, res.Request.URL.Path, err.Error())
		return
	}

	res.Body = readCloser{
		Reader: io.MultiReader(bytes.NewReader(body), res.Body),
		Closer: res.Body,
	}

	log.Printf("ERROR: %d upstream key=%s model=%s %s %s: %s", res.StatusCode, state.key, state.model, res.Request.Method, res.Request.URL.Path, oneLine(body))
}

func oneLine(body []byte) string {
	return strings.Join(strings.Fields(string(body)), " ")
}

func logRequest(state *requestState) {
	log.Printf("SESSION %s key=%s model=%s status=%d in=%s out=%s ttfb=%s total=%s", state.session, state.key, state.model, state.status, in(state.usage), out(state.usage), ttfb(state), time.Since(state.start).Round(time.Millisecond))
}

func ttfb(state *requestState) string {
	if state.header.IsZero() {
		return "-"
	}

	return state.header.Sub(state.start).Round(time.Millisecond).String()
}

func forward(z *zenProxy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := &requestState{key: key(r), start: time.Now()}
		r = r.WithContext(context.WithValue(r.Context(), stateKey{}, state))
		defer logRequest(state)

		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, z.max))
		if err != nil {
			fail(w, r, 413, fmt.Sprintf("Corpo excede o limite de %d bytes", z.max), err.Error())
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.ContentLength = int64(len(raw))

		body := prompt(raw)
		state.model = model(body)

		session := body.PromptCacheKey
		if session == "" {
			session, err = randomSession()
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
		writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
	}
}

func fail(w http.ResponseWriter, r *http.Request, code int, message string, details any) {
	state := stateOf(r.Context())
	state.status = code

	log.Printf("ERROR: %d key=%s model=%s %s %s: %s (%v)", code, state.key, state.model, r.Method, r.URL.Path, message, details)
	writeJSON(w, code, errorResponse{Code: code, Error: message, Details: details})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
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

	log.Printf("LISTENING %s -> %s", port, z.url)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), r); err != nil {
		log.Fatal(err)
	}
}