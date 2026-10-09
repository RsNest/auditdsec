package redact

import "testing"

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
