package telegram

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/i18n"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

const testToken = "123456789:AAEhBOweik6ad-secret"

type apiCall struct {
	Method string
	Body   string
}

// fakeAPI stands in for api.telegram.org.
type fakeAPI struct {
	srv *httptest.Server

	mu     sync.Mutex
	calls  []apiCall
	queue  [][]update
	failed bool
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	method := parts[len(parts)-1]
	body, _ := io.ReadAll(r.Body)

	f.mu.Lock()
	f.calls = append(f.calls, apiCall{Method: method, Body: string(body)})
	failed := f.failed
	var result any = map[string]any{"message_id": 1}
	if method == "getUpdates" {
		if len(f.queue) > 0 {
			result, f.queue = f.queue[0], f.queue[1:]
		} else {
			result = []update{}
		}
	}
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if failed {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"ok": false, "error_code": 400, "description": "Bad Request: chat not found",
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
}

func (f *fakeAPI) methods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.Method)
	}
	return out
}

// sent returns the text of every sendMessage call.
func (f *fakeAPI) sent() []sendMessageRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []sendMessageRequest
	for _, c := range f.calls {
		if c.Method != "sendMessage" {
			continue
		}
		var req sendMessageRequest
		if err := json.Unmarshal([]byte(c.Body), &req); err == nil {
			out = append(out, req)
		}
	}
	return out
}

func (f *fakeAPI) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

type clientFixture struct {
	client *Client
	api    *fakeAPI
	store  *store.Store
	now    time.Time
}

func newClient(t *testing.T, tweak func(*Options)) *clientFixture {
	t.Helper()
	api := newFakeAPI(t)
	f := &clientFixture{api: api, now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}

	// The store must share the test clock, otherwise a mute set in the test's
	// "now" looks long expired to the store's real one.
	st, err := store.Open(store.Options{Dir: t.TempDir(), Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f.store = st
	o := Options{
		Token:         testToken,
		ChatIDs:       []int64{100},
		APIBase:       api.srv.URL,
		Lang:          i18n.LangRU,
		Host:          "web01",
		Profile:       "simple",
		Store:         st,
		HTTP:          api.srv.Client(),
		Now:           func() time.Time { return f.now },
		Started:       f.now.Add(-90 * time.Minute),
		Location:      time.UTC,
		MinSeverity:   model.SevInfo,
		DedupWindow:   5 * time.Minute,
		RatePerMinute: 60,
		QuietFrom:     -1,
		QuietTo:       -1,
	}
	if tweak != nil {
		tweak(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	f.client = c
	return f
}

func loginFail(ip string) model.Event {
	return model.Event{
		Time: time.Date(2026, 10, 9, 11, 59, 0, 0, time.UTC),
		Host: "web01", Kind: model.KindSSHLoginFail, Severity: model.SevWarn,
		User: "root", SrcIP: ip, SummaryKey: "event.ssh_login_fail",
		Args: map[string]string{"user": "root", "ip": ip},
	}
}

func TestNewRequiresTokenAndChats(t *testing.T) {
	if _, err := New(Options{ChatIDs: []int64{1}}); err == nil {
		t.Error("a client without a token must not be created")
	}
	if _, err := New(Options{Token: "t"}); err == nil {
		t.Error("a client without a chat allowlist must not be created")
	}
}

func TestNotifySendsAlertWithButtons(t *testing.T) {
	f := newClient(t, nil)
	if err := f.client.Notify(context.Background(), loginFail("198.51.100.7")); err != nil {
		t.Fatal(err)
	}

	sent := f.api.sent()
	if len(sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(sent))
	}
	msg := sent[0]
	if msg.ChatID != 100 {
		t.Errorf("ChatID = %d", msg.ChatID)
	}
	if !strings.Contains(msg.Text, "web01") || !strings.Contains(msg.Text, "198.51.100.7") {
		t.Errorf("text = %q", msg.Text)
	}
	if !strings.Contains(msg.Text, "Неудачная попытка входа") {
		t.Errorf("text should be rendered in Russian: %q", msg.Text)
	}
	if msg.ReplyMarkup == nil || len(msg.ReplyMarkup.Rows) != 2 {
		t.Fatalf("keyboard = %+v", msg.ReplyMarkup)
	}
	if got := msg.ReplyMarkup.Rows[0][0].Data; got != "ban:198.51.100.7" {
		t.Errorf("ban button data = %q", got)
	}
	if got := msg.ReplyMarkup.Rows[0][1].Data; got != "allow:198.51.100.7" {
		t.Errorf("allow button data = %q", got)
	}
}

// An event without a source address must not offer a ban button for nothing.
func TestNotifyWithoutIPHasNoBanButton(t *testing.T) {
	f := newClient(t, nil)
	ev := model.Event{
		Host: "web01", Kind: model.KindSudo, Severity: model.SevInfo,
		SummaryKey: "event.sudo", Args: map[string]string{"user": "ruslan", "cmd": "apt update"},
	}
	if err := f.client.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	sent := f.api.sent()
	if len(sent) != 1 {
		t.Fatalf("sent %d", len(sent))
	}
	if sent[0].ReplyMarkup != nil {
		t.Errorf("an info event with no address should carry no buttons: %+v", sent[0].ReplyMarkup)
	}
}

func TestNotifyRespectsSeverityThreshold(t *testing.T) {
	f := newClient(t, func(o *Options) { o.MinSeverity = model.SevCritical })
	if err := f.client.Notify(context.Background(), loginFail("1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	if n := len(f.api.sent()); n != 0 {
		t.Errorf("sent %d messages, want 0 below the threshold", n)
	}
}

// 47 failures from one address must become one message plus a summary, not 47
// messages.
func TestNotifyGroupsRepeats(t *testing.T) {
	f := newClient(t, nil)
	ctx := context.Background()
	for i := 0; i < 47; i++ {
		if err := f.client.Notify(ctx, loginFail("198.51.100.7")); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(f.api.sent()); n != 1 {
		t.Fatalf("sent %d messages, want 1 while the window is open", n)
	}

	// Nothing is sent until the window closes.
	f.client.FlushGroups(ctx)
	if n := len(f.api.sent()); n != 1 {
		t.Fatalf("sent %d messages, want 1 before the window closes", n)
	}

	f.now = f.now.Add(6 * time.Minute)
	f.client.FlushGroups(ctx)
	sent := f.api.sent()
	if len(sent) != 2 {
		t.Fatalf("sent %d messages, want 2 after the window closes", len(sent))
	}
	if !strings.Contains(sent[1].Text, "46") {
		t.Errorf("the summary should count the 46 suppressed repeats: %q", sent[1].Text)
	}

	// With the window gone, the next occurrence alerts again.
	f.api.reset()
	if err := f.client.Notify(ctx, loginFail("198.51.100.7")); err != nil {
		t.Fatal(err)
	}
	if n := len(f.api.sent()); n != 1 {
		t.Errorf("sent %d messages after the window, want 1", n)
	}
}

func TestNotifyDoesNotGroupDifferentAddresses(t *testing.T) {
	f := newClient(t, nil)
	ctx := context.Background()
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		if err := f.client.Notify(ctx, loginFail(ip)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(f.api.sent()); n != 3 {
		t.Errorf("sent %d messages, want 3", n)
	}
}

func TestMuteHoldsBackOnlyNonCritical(t *testing.T) {
	f := newClient(t, nil)
	ctx := context.Background()
	if err := f.store.Mute(f.now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := f.client.Notify(ctx, loginFail("1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	if n := len(f.api.sent()); n != 0 {
		t.Errorf("a warning should be muted, sent %d", n)
	}

	crit := loginFail("1.2.3.5")
	crit.Kind = model.KindAuthorizedKeysChange
	crit.Severity = model.SevCritical
	crit.SummaryKey = "event.authorized_keys_change"
	crit.Args = map[string]string{"user": "root", "path": "/root/.ssh/authorized_keys"}
	if err := f.client.Notify(ctx, crit); err != nil {
		t.Fatal(err)
	}
	if n := len(f.api.sent()); n != 1 {
		t.Errorf("a critical event must get through a mute, sent %d", n)
	}
}

func TestQuietHours(t *testing.T) {
	// Quiet from 23:00 to 08:00, which wraps past midnight.
	f := newClient(t, func(o *Options) { o.QuietFrom = 23 * 60; o.QuietTo = 8 * 60 })
	ctx := context.Background()

	f.now = time.Date(2026, 10, 9, 23, 30, 0, 0, time.UTC)
	if err := f.client.Notify(ctx, loginFail("1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	if n := len(f.api.sent()); n != 0 {
		t.Errorf("23:30 is inside quiet hours, sent %d", n)
	}

	f.now = time.Date(2026, 10, 10, 3, 0, 0, 0, time.UTC)
	if err := f.client.Notify(ctx, loginFail("1.2.3.5")); err != nil {
		t.Fatal(err)
	}
	if n := len(f.api.sent()); n != 0 {
		t.Errorf("03:00 is inside quiet hours, sent %d", n)
	}

	f.now = time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	if err := f.client.Notify(ctx, loginFail("1.2.3.6")); err != nil {
		t.Fatal(err)
	}
	if n := len(f.api.sent()); n != 1 {
		t.Errorf("09:00 is outside quiet hours, sent %d", n)
	}
}

func TestRateLimitDropsFloods(t *testing.T) {
	f := newClient(t, func(o *Options) { o.RatePerMinute = 3 })
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		// A different address every time, so grouping does not hide the flood.
		if err := f.client.Notify(ctx, loginFail("198.51.100."+string(rune('1'+i)))); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(f.api.sent()); n != 3 {
		t.Errorf("sent %d messages, want 3 (the bucket size)", n)
	}
	if f.client.Dropped() != 7 {
		t.Errorf("Dropped = %d, want 7", f.client.Dropped())
	}

	// The bucket refills over time.
	f.now = f.now.Add(time.Minute)
	f.api.reset()
	if err := f.client.Notify(ctx, loginFail("203.0.113.1")); err != nil {
		t.Fatal(err)
	}
	if n := len(f.api.sent()); n != 1 {
		t.Errorf("sent %d messages after the refill, want 1", n)
	}
}

// The bot must ignore a chat that is not allowlisted, without so much as a
// reply that would confirm it exists.
func TestChatAllowlistRejectsStrangers(t *testing.T) {
	f := newClient(t, nil)
	ctx := context.Background()

	f.client.handleUpdate(ctx, update{
		UpdateID: 1,
		Message:  &tgMessage{Chat: tgChat{ID: 999}, Text: "/status", From: &tgUser{Username: "stranger"}},
	})
	f.client.handleUpdate(ctx, update{
		UpdateID: 2,
		Callback: &callbackQuery{ID: "cb", Data: "allow:1.2.3.4", Message: &tgMessage{Chat: tgChat{ID: 999}}},
	})

	if calls := f.api.methods(); len(calls) != 0 {
		t.Errorf("the bot answered a stranger: %v", calls)
	}
	if f.store.IsAllowed("1.2.3.4") {
		t.Error("a stranger managed to change the allowlist")
	}
}

func TestCommands(t *testing.T) {
	f := newClient(t, nil)
	ctx := context.Background()

	send := func(text string) string {
		f.api.reset()
		f.client.handleUpdate(ctx, update{Message: &tgMessage{Chat: tgChat{ID: 100}, Text: text}})
		sent := f.api.sent()
		if len(sent) == 0 {
			t.Fatalf("no reply to %q", text)
		}
		return sent[len(sent)-1].Text
	}

	if got := send("/start"); !strings.Contains(got, "web01") {
		t.Errorf("/start = %q", got)
	}
	if got := send("/help"); !strings.Contains(got, "/status") {
		t.Errorf("/help = %q", got)
	}
	if got := send("/status@auditdsec_bot"); !strings.Contains(got, "web01") || !strings.Contains(got, "1h30m") {
		t.Errorf("/status = %q", got)
	}
	if got := send("/last"); !strings.Contains(got, "Событий пока нет") {
		t.Errorf("/last with no events = %q", got)
	}
	if got := send("/allow 203.0.113.9"); !strings.Contains(got, "203.0.113.9") {
		t.Errorf("/allow = %q", got)
	}
	if !f.store.IsAllowed("203.0.113.9") {
		t.Error("/allow did not reach the store")
	}
	if got := send("/allowlist"); !strings.Contains(got, "203.0.113.9") {
		t.Errorf("/allowlist = %q", got)
	}
	if got := send("/unallow 203.0.113.9"); !strings.Contains(got, "203.0.113.9") {
		t.Errorf("/unallow = %q", got)
	}
	if f.store.IsAllowed("203.0.113.9") {
		t.Error("/unallow did not reach the store")
	}
	if got := send("/allow nonsense"); !strings.Contains(got, "nonsense") {
		t.Errorf("/allow with a bad address = %q", got)
	}
	if got := send("/allow"); !strings.Contains(got, "/allow") {
		t.Errorf("/allow without an argument = %q", got)
	}
	if got := send("/mute 2"); !strings.Contains(got, "14:00") {
		t.Errorf("/mute = %q", got)
	}
	if f.store.MutedUntil().IsZero() {
		t.Error("/mute did not reach the store")
	}
	if got := send("/unmute"); got == "" {
		t.Error("/unmute gave no reply")
	}
	if !f.store.MutedUntil().IsZero() {
		t.Error("/unmute did not clear the mute")
	}
	if got := send("/bans"); !strings.Contains(got, "Блокировок нет") {
		t.Errorf("/bans = %q", got)
	}
	if got := send("/explain ssh_login_fail"); !strings.Contains(got, "брутфорс") {
		t.Errorf("/explain = %q", got)
	}
	if got := send("/explain nonsense"); !strings.Contains(got, "nonsense") {
		t.Errorf("/explain with a bad kind = %q", got)
	}
	if got := send("/nonsense"); !strings.Contains(got, "/help") {
		t.Errorf("unknown command = %q", got)
	}
}

// /debug must say whether debug mode is on AND how to turn it on: a diagnostic
// the user cannot enable is useless.
func TestDebugCommand(t *testing.T) {
	f := newClient(t, func(o *Options) {
		o.Debug = false
		o.LogLevel = "info"
	})
	f.client.SetDiag(func() []DiagItem {
		return []DiagItem{
			{Key: "ui.diag.events", Value: "17"},
			{Key: "ui.diag.audit_log", Value: "ok, 1024 bytes, written 2s ago"},
		}
	})

	text := f.client.debugText()
	for _, want := range []string{"выключен", "info", "AUDITDSEC_DEBUG", "17", "1024 bytes"} {
		if !strings.Contains(text, want) {
			t.Errorf("/debug output should mention %q:\n%s", want, text)
		}
	}
	if !strings.Contains(text, "Событий обработано") {
		t.Errorf("diagnostic labels should be translated:\n%s", text)
	}

	on := newClient(t, func(o *Options) {
		o.Debug = true
		o.LogLevel = "debug"
	})
	if got := on.client.debugText(); !strings.Contains(got, "включён") {
		t.Errorf("debug mode is on, output = %s", got)
	}
}

func TestDebugCommandWithoutDiagnostics(t *testing.T) {
	f := newClient(t, nil)
	if got := f.client.debugText(); !strings.Contains(got, "AUDITDSEC_DEBUG") {
		t.Errorf("the hint must survive a missing diagnostics hook:\n%s", got)
	}
}

func TestDebugCommandIsReachable(t *testing.T) {
	f := newClient(t, nil)
	f.client.handleUpdate(context.Background(), update{
		Message: &tgMessage{Chat: tgChat{ID: 100}, Text: "/debug"},
	})
	sent := f.api.sent()
	if len(sent) == 0 || !strings.Contains(sent[0].Text, "AUDITDSEC_DEBUG") {
		t.Errorf("/debug = %+v", sent)
	}
}

// Grouped repeats are reported with their running count, which is what the
// debug trail needs.
func TestSuppressAsRepeatReportsCount(t *testing.T) {
	f := newClient(t, nil)
	ev := loginFail("198.51.100.7")
	if n, repeat := f.client.suppressAsRepeat(ev, f.now); repeat || n != 0 {
		t.Fatalf("first occurrence: n=%d repeat=%v", n, repeat)
	}
	for want := 1; want <= 3; want++ {
		n, repeat := f.client.suppressAsRepeat(ev, f.now)
		if !repeat || n != want {
			t.Errorf("repeat %d: n=%d repeat=%v", want, n, repeat)
		}
	}
	if f.client.OpenGroups() != 1 {
		t.Errorf("OpenGroups = %d, want 1", f.client.OpenGroups())
	}
}

func TestLastShowsNewestFirst(t *testing.T) {
	f := newClient(t, nil)
	for i, kind := range []model.Kind{model.KindSudo, model.KindSSHLoginFail} {
		ev := loginFail("1.2.3.4")
		ev.Kind = kind
		ev.SummaryKey = "event." + string(kind)
		ev.Args = map[string]string{"user": "u", "ip": "1.2.3.4", "cmd": "c"}
		ev.Time = f.now.Add(time.Duration(i) * time.Minute)
		if err := f.store.AppendEvent(ev); err != nil {
			t.Fatal(err)
		}
	}
	text := f.client.lastText(nil)
	iFail := strings.Index(text, "Неудачная попытка")
	iSudo := strings.Index(text, "повышением прав")
	if iFail < 0 || iSudo < 0 || iFail > iSudo {
		t.Errorf("newest event should come first:\n%s", text)
	}
}

func TestCallbackButtons(t *testing.T) {
	f := newClient(t, nil)
	ctx := context.Background()

	press := func(data string) string {
		f.api.reset()
		f.client.handleUpdate(ctx, update{Callback: &callbackQuery{
			ID: "cb1", Data: data, Message: &tgMessage{Chat: tgChat{ID: 100}},
		}})
		if methods := f.api.methods(); len(methods) == 0 || methods[0] != "answerCallbackQuery" {
			t.Fatalf("the button spinner was not answered: %v", methods)
		}
		sent := f.api.sent()
		if len(sent) == 0 {
			t.Fatalf("no message after pressing %q", data)
		}
		return sent[len(sent)-1].Text
	}

	if got := press("ban:198.51.100.7"); !strings.Contains(got, "198.51.100.7") {
		t.Errorf("ban = %q", got)
	}
	bans := f.store.Bans()
	if len(bans) != 1 || bans[0].IP != "198.51.100.7" {
		t.Fatalf("ban was not recorded: %+v", bans)
	}
	if bans[0].Permanent() {
		t.Error("a manual ban should expire, not be permanent")
	}

	if got := press("allow:203.0.113.9"); !strings.Contains(got, "203.0.113.9") {
		t.Errorf("allow = %q", got)
	}
	if !f.store.IsAllowed("203.0.113.9") {
		t.Error("the allow button did not reach the store")
	}

	if got := press("mute:24"); !strings.Contains(got, "2026-10-10") {
		t.Errorf("mute = %q", got)
	}
	if f.store.MutedUntil().IsZero() {
		t.Error("the mute button did not reach the store")
	}
}

// Pressing "ban" on an allowlisted address must refuse, so an owner cannot be
// locked out by a stray tap.
func TestBanButtonRefusesAllowlisted(t *testing.T) {
	f := newClient(t, nil)
	if err := f.store.Allow("203.0.113.9", "owner"); err != nil {
		t.Fatal(err)
	}
	f.client.handleUpdate(context.Background(), update{Callback: &callbackQuery{
		ID: "cb", Data: "ban:203.0.113.9", Message: &tgMessage{Chat: tgChat{ID: 100}},
	}})
	sent := f.api.sent()
	if len(sent) == 0 || !strings.Contains(sent[len(sent)-1].Text, "белом списке") {
		t.Errorf("expected a refusal, got %+v", sent)
	}
	if len(f.store.Bans()) != 0 {
		t.Error("no ban should have been recorded")
	}
}

// Values that come out of a log must not be able to inject markup.
func TestRenderEscapesEventArguments(t *testing.T) {
	f := newClient(t, nil)
	ev := model.Event{
		Host: "web01", Kind: model.KindSudo, Severity: model.SevInfo,
		SummaryKey: "event.sudo",
		Args:       map[string]string{"user": "ruslan", "cmd": `sh -c "<b>pwn</b>"`},
	}
	text := f.client.renderEvent(ev)
	if strings.Contains(text, "<b>pwn</b>") {
		t.Errorf("markup from the log was not escaped: %q", text)
	}
	if !strings.Contains(text, "&lt;b&gt;pwn&lt;/b&gt;") {
		t.Errorf("escaped form missing: %q", text)
	}
}

func TestRenderFillsMissingArgument(t *testing.T) {
	f := newClient(t, nil)
	ev := model.Event{
		Host: "web01", Kind: model.KindSSHLoginOK, Severity: model.SevInfo,
		SummaryKey: "event.ssh_login_ok",
		Args:       map[string]string{"user": "root", "ip": ""},
	}
	if got := f.client.renderEvent(ev); !strings.Contains(got, "неизвестно") {
		t.Errorf("an empty argument should read as unknown: %q", got)
	}
}

// The token is in every request URL, so it must never reach an error string.
func TestErrorsNeverLeakTheToken(t *testing.T) {
	f := newClient(t, nil)
	f.api.mu.Lock()
	f.api.failed = true
	f.api.mu.Unlock()

	err := f.client.SendTo(context.Background(), 100, "hi", nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "AAEhBOweik6ad") {
		t.Errorf("the error leaked the token: %v", err)
	}
	if !strings.Contains(err.Error(), "chat not found") {
		t.Errorf("the error should keep Telegram's explanation: %v", err)
	}
}

func TestTransportErrorNeverLeaksTheToken(t *testing.T) {
	api := newFakeAPI(t)
	url := api.srv.URL
	api.srv.Close() // nothing is listening any more

	st, err := store.Open(store.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c, err := New(Options{
		Token: testToken, ChatIDs: []int64{1}, APIBase: url, Store: st,
		HTTP: &http.Client{Timeout: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = c.SendTo(context.Background(), 1, "hi", nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "AAEhBOweik6ad") || strings.Contains(err.Error(), url) {
		t.Errorf("the error leaked the token or the URL: %v", err)
	}
}

func TestBroadcastReachesEveryChat(t *testing.T) {
	f := newClient(t, func(o *Options) { o.ChatIDs = []int64{100, 200} })
	if err := f.client.SendStartupNotice(context.Background()); err != nil {
		t.Fatal(err)
	}
	sent := f.api.sent()
	if len(sent) != 2 || sent[0].ChatID != 100 || sent[1].ChatID != 200 {
		t.Fatalf("broadcast = %+v", sent)
	}
	if !strings.Contains(sent[0].Text, "auditdsec") {
		t.Errorf("startup notice = %q", sent[0].Text)
	}
}

func TestRunBotConsumesUpdatesAndPersistsOffset(t *testing.T) {
	f := newClient(t, nil)
	f.api.mu.Lock()
	f.api.queue = [][]update{{
		{UpdateID: 41, Message: &tgMessage{Chat: tgChat{ID: 100}, Text: "/help"}},
	}}
	f.api.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.client.RunBot(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		if f.store.GetMeta(metaOffsetKey) == "42" {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatalf("offset was not persisted, meta = %q", f.store.GetMeta(metaOffsetKey))
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunBot = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("RunBot did not stop on cancel")
	}

	var sawHelp bool
	for _, s := range f.api.sent() {
		if strings.Contains(s.Text, "/status") {
			sawHelp = true
		}
	}
	if !sawHelp {
		t.Error("the /help command was not handled")
	}
}

func TestStripTags(t *testing.T) {
	if got := stripTags("<b>Hi</b> there"); got != "Hi there" {
		t.Errorf("got %q", got)
	}
}

func TestHumanDuration(t *testing.T) {
	tests := map[time.Duration]string{
		30 * time.Second: "30s",
		10 * time.Minute: "10m",
		90 * time.Minute: "1h30m",
		6 * time.Hour:    "6h",
		time.Hour:        "1h",
		0:                "0s",
	}
	for in, want := range tests {
		if got := humanDuration(in); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", in, got, want)
		}
	}
}
