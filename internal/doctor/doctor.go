// Package doctor answers the owner's first question about a quiet agent: is it
// actually working, and if not, what is broken and what to do about it.
//
// Every check only reads. It never changes the firewall, the audit rules or the
// state, never sends a message and never opens a port; the one exception is a
// short-lived probe file in the state directory to learn whether it is
// writable. A check that cannot see what it needs (for example the host's audit
// rules from inside a container) says so instead of guessing.
package doctor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/auditlog"
	"github.com/RsNest/auditdsec/internal/config"
	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/i18n"
	"github.com/RsNest/auditdsec/internal/semantic"
	"github.com/RsNest/auditdsec/internal/store"
)

// Level is how serious a finding is.
type Level int

const (
	OK   Level = iota // works
	Info              // nothing wrong, worth knowing
	Warn              // works, but something needs attention
	Fail              // broken: the agent cannot do its job here
)

func (l Level) String() string { return [...]string{"OK", "INFO", "WARN", "FAIL"}[l] }

// Finding is one result: what was checked, what is the case, how to fix it.
type Finding struct {
	Area  string
	Level Level
	What  string
	Fix   string // empty when nothing needs doing
}

// Report is the outcome of a run.
type Report struct{ Findings []Finding }

// Worst returns the most serious level present.
func (r Report) Worst() Level {
	w := OK
	for _, f := range r.Findings {
		if f.Level > w {
			w = f.Level
		}
	}
	return w
}

// Options carries the configuration and every outside dependency, so the checks
// can be tested with fakes.
type Options struct {
	Config     *config.Config
	RulesPaths []string
	Now        func() time.Time
	LookPath   func(string) (string, error)
	// Run executes a read-only command and returns its output.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// Get fetches a URL and returns the status code.
	Get func(ctx context.Context, url string) (int, error)
}

func (o *Options) defaults() {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.LookPath == nil {
		o.LookPath = exec.LookPath
	}
	if o.Run == nil {
		o.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	if o.Get == nil {
		o.Get = func(ctx context.Context, url string) (int, error) {
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return 0, err
			}
			resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
			if err != nil {
				return 0, err
			}
			resp.Body.Close()
			return resp.StatusCode, nil
		}
	}
}

// ConfigFailure is the report for a configuration that does not load.
func ConfigFailure(lang i18n.Lang, err error) Report {
	t := tr(lang)
	return Report{Findings: []Finding{{
		Area: t("Configuration", "Конфигурация"), Level: Fail,
		What: t("The configuration does not load: ", "Конфигурация не загружается: ") + err.Error(),
		Fix: t("Fix the line named above, then run `auditdsec check-config` until it says the configuration is valid.",
			"Исправьте указанную строку и запускайте `auditdsec check-config`, пока он не напишет, что конфигурация верна."),
	}}}
}

func tr(lang i18n.Lang) func(en, ru string) string {
	return func(en, ru string) string {
		if lang == i18n.LangRU {
			return ru
		}
		return en
	}
}

// Run performs every check.
func Run(ctx context.Context, o Options) Report {
	o.defaults()
	d := &doc{o: o, t: tr(o.Config.Language()), ctx: ctx}
	d.state()
	d.auditLog()
	d.rules()
	d.firewall()
	d.decisions()
	d.queue()
	d.panel()
	return Report{Findings: d.out}
}

type doc struct {
	o   Options
	t   func(en, ru string) string
	out []Finding
	ctx context.Context
}

func (d *doc) add(area string, l Level, what, fix string) {
	d.out = append(d.out, Finding{Area: area, Level: l, What: what, Fix: fix})
}

func (d *doc) state() {
	c := d.o.Config
	area := d.t("State directory", "Каталог состояния")
	fi, err := os.Stat(c.StateDir)
	switch {
	case err != nil && os.IsNotExist(err):
		d.add(area, Info, d.t(c.StateDir+" does not exist yet; the agent creates it on first start.", c.StateDir+" ещё не создан; агент создаст его при первом запуске."), "")
		return
	case err != nil:
		d.add(area, Fail, fmt.Sprintf("%s: %v", c.StateDir, err), d.t("Give the agent's user access to the directory.", "Дайте пользователю агента доступ к каталогу."))
		return
	case !fi.IsDir():
		d.add(area, Fail, c.StateDir+d.t(" is not a directory.", " — не каталог."), d.t("Point state_dir at a directory.", "Укажите в state_dir каталог."))
		return
	}
	probe, err := os.CreateTemp(c.StateDir, ".doctor-*")
	if err != nil {
		d.add(area, Fail, fmt.Sprintf(d.t("%s is not writable: %v", "%s недоступен для записи: %v"), c.StateDir, err),
			d.t("Without it nothing is remembered: bans, progress and queued alerts are lost. Fix the owner/permissions of the directory (or the volume mount in Docker).",
				"Без него ничего не запоминается: баны, прогресс и очередь уведомлений теряются. Исправьте владельца и права каталога (или монтирование тома в Docker)."))
		return
	}
	name := probe.Name()
	probe.Close()
	_ = os.Remove(name)
	d.add(area, OK, d.t(c.StateDir+" is writable.", c.StateDir+" доступен для записи."), "")
}

func (d *doc) auditLog() {
	c := d.o.Config
	area := d.t("Audit log", "Журнал аудита")
	stale := time.Duration(0)
	if c.Heartbeat.Enabled {
		stale = c.Heartbeat.StaleAfter
	}
	st := auditlog.Check(c.AuditLog, d.o.Now(), stale)
	switch st.State {
	case auditlog.OK:
		d.add(area, OK, fmt.Sprintf(d.t("%s is readable and was written %s ago.", "%s читается, последняя запись была %s назад."),
			c.AuditLog, d.o.Now().Sub(st.LastWrite).Round(time.Second)), "")
	case auditlog.Unavailable:
		d.add(area, Fail, d.t("The agent cannot read the audit log, so it sees nothing: ", "Агент не может прочитать журнал аудита и ничего не видит: ")+st.Detail,
			d.t("Check that auditd is installed and running (`systemctl status auditd`), that audit_log in the configuration is the real path (usually /var/log/audit/audit.log), "+
				"and that the agent's user may read it. In Docker the directory must be mounted into the container read-only.",
				"Проверьте, что auditd установлен и запущен (`systemctl status auditd`), что audit_log в конфигурации указывает на настоящий файл (обычно /var/log/audit/audit.log) "+
					"и что пользователь агента может его читать. В Docker каталог должен быть смонтирован в контейнер только для чтения."))
	case auditlog.Silent:
		d.add(area, Warn, d.t("The log is readable but silent: ", "Журнал читается, но молчит: ")+st.Detail,
			d.t("A quiet server looks the same as a stopped auditd. Check `systemctl status auditd` and `auditctl -s` (enabled should be 1), then run `sudo true` and see whether a new line appears. "+
				"If auditd is fine, raise heartbeat.stale_after for a very quiet host.",
				"Тихий сервер выглядит так же, как остановленный auditd. Проверьте `systemctl status auditd` и `auditctl -s` (enabled должен быть 1), затем выполните `sudo true` и посмотрите, появилась ли новая строка. "+
					"Если auditd в порядке, увеличьте heartbeat.stale_after для очень тихого сервера."))
	}
}

func (d *doc) rules() {
	area := d.t("Audit rules", "Правила аудита")
	paths := d.o.RulesPaths
	if len(paths) == 0 {
		paths = []string{"/etc/audit/rules.d", "/etc/audit/audit.rules"}
	}
	rep, err := auditlog.CheckRules(paths, semantic.RequiredKeys())
	switch {
	case err != nil:
		d.add(area, Warn, d.t("The rule files could not be read: ", "Файлы правил не читаются: ")+err.Error(),
			d.t("Run `auditdsec check-rules` on the host as root.", "Запустите `auditdsec check-rules` на хосте от root."))
	case len(rep.Files) == 0:
		d.add(area, Info, d.t("No audit rule files are visible from here (normal inside a container).", "Файлы правил аудита отсюда не видны (нормально внутри контейнера)."),
			d.t("Run `auditdsec check-rules` on the host. Rules are only needed for files and system calls; logins and sudo are recorded without them.",
				"Запустите `auditdsec check-rules` на хосте. Правила нужны только для файлов и системных вызовов; входы и sudo пишутся и без них."))
	case !rep.OK():
		d.add(area, Fail, d.t("Rules for these event classes are missing, so such events are never produced: ", "Нет правил для этих классов событий, поэтому такие события никогда не появятся: ")+strings.Join(rep.Missing, ", "),
			d.t("Install deploy/auditdsec.rules into /etc/audit/rules.d/50-auditdsec.rules and run `sudo augenrules --load`; confirm with `sudo auditctl -l`.",
				"Установите deploy/auditdsec.rules в /etc/audit/rules.d/50-auditdsec.rules и выполните `sudo augenrules --load`; проверьте `sudo auditctl -l`."))
	default:
		d.add(area, OK, d.t("All required audit keys are present in the rule files. (Files only: `auditctl -l` shows what the kernel has loaded.)",
			"Все нужные ключи аудита есть в файлах правил. (Только файлы: что загружено в ядро, показывает `auditctl -l`.)"), "")
	}
}

func (d *doc) firewall() {
	c := d.o.Config
	area := d.t("Firewall", "Файрвол")
	switch {
	case c.Ban.Backend != config.BanBackendNftables:
		d.add(area, Info, d.t("ban.backend is none: ban decisions are recorded and reported but nothing is blocked.", "ban.backend = none: решения о банах записываются и отправляются, но ничего не блокируется."),
			d.t("To block addresses set ban.backend: nftables and start the agent with deploy/compose.enforce.yml (NET_ADMIN, host network). Try ban.dry_run: true first.",
				"Чтобы блокировать адреса, задайте ban.backend: nftables и запустите агент с deploy/compose.enforce.yml (NET_ADMIN, сеть хоста). Сначала попробуйте ban.dry_run: true."))
		return
	case c.Ban.DryRun:
		d.add(area, Info, d.t("ban.dry_run is on: the exact nft commands are logged, nothing is blocked.", "ban.dry_run включён: точные команды nft пишутся в лог, ничего не блокируется."),
			d.t("When the logged commands look right, set ban.dry_run: false.", "Когда команды в логе выглядят правильно, поставьте ban.dry_run: false."))
		return
	}
	if _, err := d.o.LookPath("nft"); err != nil {
		d.add(area, Fail, d.t("ban.backend is nftables but the `nft` program is not found.", "ban.backend = nftables, но программа `nft` не найдена."),
			d.t("Install nftables (apt install nftables), or use the enforce image, which contains it.", "Установите nftables (apt install nftables) или используйте образ enforce, где она есть."))
		return
	}
	out, err := d.o.Run(d.ctx, "nft", "list", "table", "inet", c.Ban.Table)
	if err != nil {
		d.add(area, Warn, fmt.Sprintf(d.t("`nft list table inet %s` failed: %v", "`nft list table inet %s` завершилась ошибкой: %v"), c.Ban.Table, oneLine(err.Error()+" "+string(out))),
			d.t("Either the agent has not created its table yet (it does so at start), or this user lacks the NET_ADMIN capability/root. Run doctor as root on the host, or check the agent log for 'the firewall refused'.",
				"Либо агент ещё не создал свою таблицу (он делает это при запуске), либо у пользователя нет NET_ADMIN/root. Запустите doctor от root на хосте или поищите в логе агента 'the firewall refused'."))
		return
	}
	d.add(area, OK, fmt.Sprintf(d.t("nftables table inet %s exists and can be read.", "таблица nftables inet %s существует и читается."), c.Ban.Table), "")
}

func (d *doc) decisions() {
	c := d.o.Config
	area := d.t("Ban decisions and detection", "Решения о банах и детекция")
	info, err := store.InspectState(c.StateDir)
	if err != nil {
		d.add(area, Fail, d.t("state.json cannot be read: ", "state.json не читается: ")+err.Error(),
			d.t("Do not delete it. Restore it from a backup; without it bans and detection progress are lost.", "Не удаляйте его. Восстановите из резервной копии; без него теряются баны и прогресс детекции."))
		return
	}
	if !info.Exists {
		d.add(area, Info, d.t("No state yet: the agent has not run here.", "Состояния пока нет: агент здесь ещё не запускался."), "")
		return
	}
	failed, pending := info.BansByState[store.StateFailed], info.BansByState[store.StatePending]
	switch {
	case failed > 0:
		d.add(area, Warn, fmt.Sprintf(d.t("%d ban(s) could not be enforced by the firewall.", "%d бан(ов) не удалось применить в файрволе."), failed),
			d.t("The agent retries on its own. If it keeps failing see the last_error of each ban in the panel or the log (usually missing NET_ADMIN or a broken nft).",
				"Агент повторяет попытки сам. Если не проходит, смотрите last_error у каждого бана в панели или в логе (обычно нет NET_ADMIN или сломан nft)."))
	case pending > 0:
		d.add(area, Warn, fmt.Sprintf(d.t("%d ban(s) are recorded but not yet confirmed in the firewall.", "%d бан(ов) записаны, но ещё не подтверждены в файрволе."), pending),
			d.t("Normal for a few seconds. If it persists, the agent is not running or cannot reach the firewall.", "Нормально несколько секунд. Если не проходит, агент не запущен или не достаёт до файрвола."))
	default:
		d.add(area, OK, fmt.Sprintf(d.t("%d ban record(s), none waiting for the firewall; %d allowlist entr(ies).", "Записей о банах: %d, ни одна не ждёт файрвола; записей белого списка: %d."), sum(info.BansByState), info.Allowlist), "")
	}
	if info.Releases > 0 {
		d.add(area, Warn, fmt.Sprintf(d.t("%d unblock(s) are not yet confirmed by the firewall.", "%d разблокировок ещё не подтверждены файрволом."), info.Releases),
			d.t("The address is free in the records but may still be blocked. The agent retries; check the firewall if it persists.", "В записях адрес свободен, но может оставаться заблокированным. Агент повторяет; если не проходит, проверьте файрвол."))
	}
	if info.NoticesOwed > 0 {
		d.add(area, Info, fmt.Sprintf(d.t("%d ban notice(s) are owed and will be sent when the agent runs.", "%d уведомлений о банах ждут отправки; уйдут, когда агент работает."), info.NoticesOwed), "")
	}
	switch {
	case !c.Detect.Enabled:
		d.add(area, Warn, d.t("The brute-force detector is disabled.", "Детектор перебора паролей отключён."), d.t("Set detect.enabled: true.", "Включите detect.enabled: true."))
	case !info.DetectInitialized:
		d.add(area, Info, d.t("Detection progress will be initialized at the next start (events written before that are history).", "Прогресс детекции будет создан при следующем запуске (события до этого считаются историей)."), "")
	case info.BacklogBytes > 0:
		d.add(area, Info, fmt.Sprintf(d.t("%d KiB of journaled events in %d day file(s) await detection; the agent judges them at start and as it runs.", "%d КиБ записанных событий в %d файлах дней ждут детекции; агент разберёт их при запуске и в работе."), info.BacklogBytes/1024+1, info.BacklogDays), "")
	default:
		d.add(area, OK, d.t("Detection has consumed every journaled event.", "Детекция обработала все записанные события."), "")
	}
}

func (d *doc) queue() {
	c := d.o.Config
	area := d.t("Notification queue", "Очередь уведомлений")
	if c.Telegram.Token == "" || len(c.Telegram.ChatIDs) == 0 {
		d.add(area, Info, d.t("Telegram is not configured (token or chat id missing): alerts are stored and shown in the panel but not sent.", "Telegram не настроен (нет токена или chat id): события сохраняются и видны в панели, но не отправляются."),
			d.t("Set telegram.token and telegram.chat_ids, or configure them in the panel's alert settings.", "Задайте telegram.token и telegram.chat_ids или настройте их в разделе уведомлений панели."))
	}
	wal := filepath.Join(c.StateDir, "outbox", "outbox.wal")
	if _, err := os.Stat(wal); err != nil {
		d.add(area, Info, d.t("No notification queue exists yet.", "Очереди уведомлений пока нет."), "")
		return
	}
	// Open a copy: the live queue belongs to the running agent.
	tmp, err := os.MkdirTemp("", "doctor-outbox-")
	if err != nil {
		d.add(area, Warn, d.t("Cannot make a temporary copy to inspect the queue: ", "Не удаётся сделать временную копию для проверки очереди: ")+err.Error(), "")
		return
	}
	defer os.RemoveAll(tmp)
	if err := copyFile(wal, filepath.Join(tmp, "outbox", "outbox.wal")); err != nil {
		d.add(area, Warn, d.t("Cannot read the queue file: ", "Не удаётся прочитать файл очереди: ")+err.Error(), "")
		return
	}
	q, err := delivery.Open(delivery.Options{Dir: filepath.Join(tmp, "outbox")})
	if err != nil {
		d.add(area, Fail, d.t("The notification queue is damaged: ", "Очередь уведомлений повреждена: ")+err.Error(),
			d.t("Do not delete it blindly: it holds alerts that were not sent yet. Restore it from a backup, or contact support with this message.", "Не удаляйте её вслепую: в ней неотправленные уведомления. Восстановите из резервной копии или обратитесь за помощью с этим сообщением."))
		return
	}
	defer q.Close()
	s := q.Stats()
	fails := q.Failures()
	switch {
	case len(fails) > 0:
		f := fails[len(fails)-1]
		d.add(area, Warn, fmt.Sprintf(d.t("%d notification(s) are pending, %d failed permanently. Last failure: %s (%s)", "В очереди %d уведомлений, безвозвратно не доставлено %d. Последняя ошибка: %s (%s)"), s.Pending, s.Failed, oneLine(f.Reason), f.At.Format(time.RFC3339)),
			d.t("Typical causes: a wrong or revoked bot token, a chat id the bot may not write to (open the bot and press Start), or no route to api.telegram.org. Fix it, then use the panel's test message.",
				"Типичные причины: неверный или отозванный токен бота, chat id, куда бот не может писать (откройте бота и нажмите Start), или нет маршрута до api.telegram.org. Исправьте и отправьте тест из панели."))
	case s.Pending > 0:
		d.add(area, Info, fmt.Sprintf(d.t("%d notification(s) are waiting to be sent (%d critical).", "Ждут отправки %d уведомлений (критичных: %d)."), s.Pending, s.Critical),
			d.t("Normal while the agent is running and the network is up. If the number does not fall, check the token and network.", "Нормально, пока агент работает и есть сеть. Если число не уменьшается, проверьте токен и сеть."))
	default:
		d.add(area, OK, fmt.Sprintf(d.t("The queue is empty; %d delivered, %d suppressed by policy.", "Очередь пуста; доставлено %d, подавлено политикой %d."), s.Delivered, s.Suppressed), "")
	}
	if s.Overflow > 0 {
		d.add(area, Warn, fmt.Sprintf(d.t("%d routine notification(s) were dropped because the queue was full.", "%d рядовых уведомлений отброшено из-за переполнения очереди."), s.Overflow),
			d.t("Events are still stored. Raise telegram.min_severity or fix delivery so the queue drains.", "События сохранены. Поднимите telegram.min_severity или почините доставку, чтобы очередь разгружалась."))
	}
}

func (d *doc) panel() {
	c := d.o.Config
	area := d.t("Web panel", "Веб-панель")
	if !c.Web.Enabled {
		d.add(area, Info, d.t("The panel is off.", "Панель выключена."), d.t("Enable it with web.enabled: true (the installer does this).", "Включите web.enabled: true (установщик делает это сам)."))
		return
	}
	code, err := d.o.Get(d.ctx, "http://"+c.Web.Listen+"/")
	if err != nil {
		d.add(area, Fail, fmt.Sprintf(d.t("Nothing answers on %s: %v", "На %s никто не отвечает: %v"), c.Web.Listen, oneLine(err.Error())),
			d.t("The agent is not running, or web.listen differs from what it was started with. Check `docker compose ps` / `systemctl status auditdsec` and the agent log.",
				"Агент не запущен или web.listen отличается от того, с чем он запущен. Проверьте `docker compose ps` / `systemctl status auditdsec` и лог агента."))
		return
	}
	d.add(area, OK, fmt.Sprintf(d.t("The panel answers on %s (HTTP %d).", "Панель отвечает на %s (HTTP %d)."), c.Web.Listen, code), "")
	if c.Web.PasswordHash == "" && c.Web.Password == "" {
		d.add(area, Info, d.t("No password is set in the configuration: until credentials are chosen in the panel, the first sign-in is admin / admin and it only lets you set new ones.",
			"В конфигурации нет пароля: пока в панели не заданы свои данные, первый вход — admin / admin, и он позволяет только задать новые."),
			d.t("Open the panel and complete the credential setup.", "Откройте панель и завершите настройку учётных данных."))
	}
	if c.Web.PublicURL != "" && !strings.HasPrefix(c.Web.PublicURL, "https://") {
		d.add(area, Warn, d.t("public_url is not HTTPS: ", "public_url не HTTPS: ")+c.Web.PublicURL,
			d.t("Credentials would travel unencrypted. Publish the panel through the TLS proxy (./install.sh).", "Учётные данные пойдут без шифрования. Публикуйте панель через TLS-прокси (./install.sh)."))
	}
}

// Write renders the report for a person.
func Write(w io.Writer, lang i18n.Lang, r Report) {
	t := tr(lang)
	fmt.Fprintln(w, t("auditdsec doctor — read-only checks, nothing was changed.", "auditdsec doctor — проверки только для чтения, ничего не изменено."))
	for _, f := range r.Findings {
		fmt.Fprintf(w, "\n[%-4s] %s\n       %s\n", f.Level, f.Area, f.What)
		if f.Fix != "" {
			fmt.Fprintf(w, "       → %s\n", f.Fix)
		}
	}
	fmt.Fprintln(w)
	switch r.Worst() {
	case Fail:
		fmt.Fprintln(w, t("Result: something is broken (FAIL). Fix the items marked FAIL first.", "Итог: что-то сломано (FAIL). Сначала исправьте пункты с FAIL."))
	case Warn:
		fmt.Fprintln(w, t("Result: working, but needs attention (WARN).", "Итог: работает, но требует внимания (WARN)."))
	default:
		fmt.Fprintln(w, t("Result: everything that could be checked from here is fine.", "Итог: всё, что можно проверить отсюда, в порядке."))
	}
	fmt.Fprintln(w, t("Not checked here: that the kernel really delivers events and that Telegram accepts a message. Use the panel's test message and `sudo true` to see them end to end.",
		"Здесь не проверяется: что ядро действительно доставляет события и что Telegram принимает сообщение. Увидеть это целиком можно тестовым сообщением из панели и командой `sudo true`."))
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func copyFile(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
