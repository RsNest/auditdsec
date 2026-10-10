package redact

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"nothing to mask", "/usr/bin/apt-get install nginx", "/usr/bin/apt-get install nginx"},
		{"password kv", "mysql --user=root password=hunter2", "mysql --user=root password=***"},
		{"quoted token", `curl -d token="abc123"`, "curl -d token=***"},
		{"colon form", "secret: topsecret", "secret: ***"},
		{"long opt", "restic --password s3cr3t backup", "restic --password *** backup"},
		{"auth header", `curl -H "Authorization: Bearer eyJhbGciOi" https://x`, `curl -H "Authorization: Bearer ***" https://x`},
		{"url creds", "git clone https://bob:pa55@github.com/x/y", "git clone https://bob:***@github.com/x/y"},
		{"mysql short opt", "mysqldump -uroot -phunter2 db", "mysqldump -uroot -p*** db"},
		{"short opt left alone without db tool", "cp -pr /a /b", "cp -pr /a /b"},
		{"api key underscore", "export API_KEY=AKIAIOSFODNN7", "export API_KEY=***"},
		{"api-key dash", "foo --api-key=zzz bar", "foo --api-key=*** bar"},
		{"several secrets", "app --token t1 password=p2", "app --token *** password=***"},
		{"passphrase", "ssh-keygen -N passphrase=abc", "ssh-keygen -N passphrase=***"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := String(tc.in); got != tc.want {
				t.Errorf("String(%q)\n got %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestStringLeavesHarmlessFlagsAlone(t *testing.T) {
	// Regression guard: these must not be touched, they are everyday commands.
	for _, s := range []string{
		"mkdir -p /var/lib/auditdsec",
		"install -p -m 0644 file /etc",
		"tar -xpf archive.tar",
		"systemctl restart sshd",
	} {
		if got := String(s); got != s {
			t.Errorf("String(%q) = %q, want unchanged", s, got)
		}
	}
}

func TestArgs(t *testing.T) {
	in := map[string]string{"cmd": "mysql password=abc", "path": "/etc/passwd"}
	out := Args(in)
	if out["cmd"] != "mysql password=***" {
		t.Errorf("cmd = %q", out["cmd"])
	}
	if out["path"] != "/etc/passwd" {
		t.Errorf("path = %q", out["path"])
	}
	if in["cmd"] != "mysql password=abc" {
		t.Error("Args must not modify its input")
	}
	if Args(nil) != nil {
		t.Error("Args(nil) must stay nil")
	}
}

func TestToken(t *testing.T) {
	tests := map[string]string{
		"":                       "",
		"123456789:AAEhBOweik":   "123456789:***",
		"abcd":                   "***",
		"abcdefghijklmnopqrstuv": "ab***",
	}
	for in, want := range tests {
		if got := Token(in); got != want {
			t.Errorf("Token(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStringJSONAndEnvNames(t *testing.T) {
	tests := map[string]string{
		`curl -d '{"password": "hunter2", "user": "bob"}' x`: `curl -d '{"password": "***", "user": "bob"}' x`,
		`{"api_key":"abc123"}`:                               `{"api_key":"***"}`,
		"MYSQL_PWD=hunter2 mysqldump db":                     "MYSQL_PWD=*** mysqldump db",
		"PGPASSWORD=hunter2 psql":                            "PGPASSWORD=*** psql",
		"Cookie: session=abcdef":                             "Cookie: ***",
		"bypass=1 passenger=2":                               "bypass=1 passenger=2",
	}
	for in, want := range tests {
		if got := String(in); got != want {
			t.Errorf("String(%q)\n got %q\nwant %q", in, got, want)
		}
		if got := String(String(in)); got != String(in) {
			t.Errorf("String is not idempotent on %q: %q", in, got)
		}
	}
}

// A secret that is a separate argument is invisible to flat text patterns;
// the argument vector sees it.
func TestArgvMasksSeparateArguments(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"long option value", []string{"restic", "--password", "s3cr3t", "backup"}, []string{"restic", "--password", "***", "backup"}},
		{"long option equals", []string{"app", "--token=abc", "x"}, []string{"app", "--token=***", "x"}},
		{"sshpass", []string{"sshpass", "-p", "hunter2", "ssh", "host"}, []string{"sshpass", "-p", "***", "ssh", "host"}},
		{"sshpass under sudo", []string{"sudo", "-u", "bob", "sshpass", "-phunter2", "ssh"}, []string{"sudo", "-u", "bob", "sshpass", "-p***", "ssh"}},
		{"mysql attached", []string{"mysql", "-uroot", "-phunter2", "db"}, []string{"mysql", "-uroot", "-p***", "db"}},
		{"mysql prompt", []string{"mysql", "-p", "db"}, []string{"mysql", "-p", "db"}},
		{"redis", []string{"redis-cli", "-a", "hunter2", "ping"}, []string{"redis-cli", "-a", "***", "ping"}},
		{"curl user", []string{"curl", "-u", "bob:hunter2", "https://x"}, []string{"curl", "-u", "bob:***", "https://x"}},
		{"curl header", []string{"curl", "-H", "Authorization: Bearer abc", "https://x"}, []string{"curl", "-H", "Authorization: ***", "https://x"}},
		{"curl cookie", []string{"curl", "-b", "sid=abc", "https://x"}, []string{"curl", "-b", "***", "https://x"}},
		{"env assignment", []string{"env", "PGPASSWORD=hunter2", "psql"}, []string{"env", "PGPASSWORD=***", "psql"}},
		{"docker env flag", []string{"docker", "run", "-e", "DB_PASSWORD=hunter2", "img"}, []string{"docker", "run", "-e", "DB_PASSWORD=***", "img"}},
		{"docker login", []string{"docker", "login", "-u", "bob", "-p", "hunter2"}, []string{"docker", "login", "-u", "bob", "-p", "***"}},
		{"openssl passin", []string{"openssl", "rsa", "-passin", "pass:hunter2"}, []string{"openssl", "rsa", "-passin", "***"}},
		{"keyword", []string{"mysqladmin", "-u", "root", "password", "newpass"}, []string{"mysqladmin", "-u", "root", "password", "***"}},
		{"openssl passwd", []string{"openssl", "passwd", "-1", "hunter2"}, []string{"openssl", "passwd", "-1", "***"}},
		{"useradd hash", []string{"useradd", "-p", "$6$salt$hash", "bob"}, []string{"useradd", "-p", "***", "bob"}},
		{"htpasswd", []string{"htpasswd", "-b", "/etc/x", "bob", "hunter2"}, []string{"htpasswd", "-b", "/etc/x", "bob", "***"}},
		{"chpasswd", []string{"echo", "root:hunter2", "|", "chpasswd"}, []string{"echo", "root:***", "|", "chpasswd"}},
		{"url credentials", []string{"git", "clone", "https://bob:pa55@h/x"}, []string{"git", "clone", "https://bob:***@h/x"}},
		// harmless everyday commands stay as they are
		{"mkdir -p", []string{"mkdir", "-p", "/var/lib/x"}, []string{"mkdir", "-p", "/var/lib/x"}},
		{"ssh port", []string{"ssh", "-p", "2222", "host"}, []string{"ssh", "-p", "2222", "host"}},
		{"docker run port", []string{"docker", "run", "-p", "80:80", "img"}, []string{"docker", "run", "-p", "80:80", "img"}},
		{"docker run user", []string{"docker", "run", "--user", "1000:1000", "img"}, []string{"docker", "run", "--user", "1000:1000", "img"}},
		{"passwd tool", []string{"passwd", "root"}, []string{"passwd", "root"}},
		{"password file option", []string{"app", "--password-file", "/run/x"}, []string{"app", "--password-file", "/run/x"}},
		{"PWD", []string{"env", "PATH=/bin", "ls"}, []string{"env", "PATH=/bin", "ls"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := append([]string(nil), tc.in...)
			got := Argv(tc.in)
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Errorf("Argv(%q)\n got %q\nwant %q", in, got, tc.want)
			}
			if again := Argv(got); strings.Join(again, "\x00") != strings.Join(got, "\x00") {
				t.Errorf("Argv is not idempotent: %q then %q", got, again)
			}
			if strings.Join(tc.in, "\x00") != strings.Join(in, "\x00") {
				t.Error("Argv modified its input")
			}
		})
	}
}

func TestCommandKeepsQuotingOfUntouchedWords(t *testing.T) {
	tests := map[string]string{
		`grep "a b" file`:                         `grep "a b" file`,
		`mysql -u root -phunter2 -e 'select 1'`:   `mysql -u root -p*** -e 'select 1'`,
		`sshpass -p 'hunter 2' ssh host`:          `sshpass -p *** ssh host`,
		`curl -H "Authorization: Bearer abc" url`: `curl -H 'Authorization: ***' url`,
		`echo it's fine && mysql -phunter2`:       `echo it's fine && mysql -p***`, // unbalanced quote: split on spaces
		`echo root:hunter2 | chpasswd`:            `echo root:*** | chpasswd`,
		`restic --password=s3cr3t backup`:         `restic --password=*** backup`,
		"  ls   -l  ":                             "ls -l",
	}
	for in, want := range tests {
		if got := Command(in); got != want {
			t.Errorf("Command(%q)\n got %q\nwant %q", in, got, want)
		}
		if got := Command(Command(in)); got != Command(in) {
			t.Errorf("Command is not idempotent on %q: %q", in, got)
		}
	}
}

// Bounded work: a huge or hostile command line does not blow up.
func TestCommandIsBounded(t *testing.T) {
	long := strings.Repeat("a ", 100000) + "--password hunter2"
	got := Command(long)
	if strings.Contains(got, "hunter2") {
		t.Error("the secret after the word limit survived")
	}
	if n := len(SplitCommand(long)); n > maxTokens+1 {
		t.Errorf("%d words examined", n)
	}
}
