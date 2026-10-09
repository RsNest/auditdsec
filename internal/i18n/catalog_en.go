package i18n

// catalogEN mirrors catalogRU key for key, placeholder for placeholder.
var catalogEN = map[string]string{
	// Event summaries.
	"event.ssh_login_ok":           "Login: {user} from {ip}",
	"event.ssh_login_fail":         "Failed login attempt: {user} from {ip}",
	"event.sudo":                   "{user} ran a command with elevated rights: {cmd}",
	"event.user_change":            "Account change: {detail}",
	"event.authorized_keys_change": "SSH key file {path} changed by {user}",
	"event.persistence":            "Startup object {path} changed by {user}",
	"event.config_change":          "Configuration file {path} changed by {user}",
	"event.log_tamper":             "Logs or audit rules tampered with: {detail}, user {user}",
	"event.suspicious_exec":        "Program executed from a temporary directory: {path}, user {user}",
	"event.auditd_stopped":         "Audit service unavailable: {detail}",
	"event.unknown":                "Event {kind}",

	// Severity labels.
	"sev.info":     "info",
	"sev.warn":     "warning",
	"sev.critical": "critical",

	// `explain` texts: what it is, how dangerous, what to do.
	"explain.ssh_login_ok": "What it is: somebody logged in successfully.\n" +
		"Risk: a login is ordinary, but a root login or one from an unfamiliar address deserves a look — especially right after a burst of failures.\n" +
		"What to do: if it was not you, rotate passwords and SSH keys now, inspect ~/.ssh/authorized_keys and check live sessions with who.",
	"explain.ssh_login_fail": "What it is: a login attempt with wrong credentials.\n" +
		"Risk: isolated misses are normal. Dozens per minute mean a brute-force attack.\n" +
		"What to do: ban the address with the button under the message, then disable password logins (PasswordAuthentication no) and keep keys only.",
	"explain.sudo": "What it is: a user ran a command as root through sudo or su.\n" +
		"Risk: routine administration. Worrying when the user should not be doing it, or when the command downloads and runs code from the internet.\n" +
		"What to do: check the command and the user. If it was not you, treat that account as compromised.",
	"explain.user_change": "What it is: accounts, groups or sudo rights were created, removed or modified.\n" +
		"Risk: high. A hidden account is a classic way to keep access to a server.\n" +
		"What to do: review the user list (getent passwd) and /etc/sudoers, and delete anything unexpected.",
	"explain.authorized_keys_change": "What it is: the authorized_keys file that grants password-less SSH access was changed.\n" +
		"Risk: very high. With their own key in place, an attacker returns whenever they like, even after a password change.\n" +
		"What to do: open the file, remove unknown keys, then find out who added them and when.",
	"explain.persistence": "What it is: cron jobs, systemd units or shell startup files were changed.\n" +
		"Risk: high. This is how malicious code survives a reboot.\n" +
		"What to do: read the changed file, check crontab -l for every user and systemctl list-timers.",
	"explain.config_change": "What it is: a service configuration file such as sshd_config was changed.\n" +
		"Risk: medium. Configuration is where root logins get enabled, passwords get allowed and tunnels get added.\n" +
		"What to do: compare the file with its expected state and restart the service if the change was unwanted.",
	"explain.log_tamper": "What it is: logs or audit rules were modified, or a kernel module was loaded.\n" +
		"Risk: very high. This is track covering, and afterwards the logs cannot be trusted.\n" +
		"What to do: preserve a copy of the logs, inspect the system from external media and treat the server as compromised until proven otherwise.",
	"explain.suspicious_exec": "What it is: a program was executed from /tmp, /dev/shm or /var/tmp.\n" +
		"Risk: high. Normal services do not run from there, but loaders and miners do.\n" +
		"What to do: inspect the file and the process; when in doubt kill the process and delete the file.",
	"explain.auditd_stopped": "What it is: the audit service is not writing events, or has stopped.\n" +
		"Risk: high. While auditing is off you cannot see what happens on the server.\n" +
		"What to do: check systemctl status auditd and start the service. If you did not stop it, find out who did.",

	// Bot UI.
	"ui.btn.ban":  "🚫 Ban {ip}",
	"ui.btn.me":   "✅ That was me",
	"ui.btn.mute": "🔕 Mute 24h",
	"ui.started":  "auditdsec started on <b>{host}</b>. Profile: {profile}.",
	"ui.start": "Linked: this chat will receive events from host <b>{host}</b>.\n\n" +
		"Commands: /help",
	"ui.help": "<b>auditdsec commands</b>\n" +
		"/status — agent state\n" +
		"/last [N] — recent events\n" +
		"/allow &lt;IP&gt; — add an address to the allowlist\n" +
		"/unallow &lt;IP&gt; — remove an address from the allowlist\n" +
		"/allowlist — show the allowlist\n" +
		"/bans — ban decisions\n" +
		"/unban &lt;IP&gt; — lift a ban\n" +
		"/mute [hours] — mute alerts\n" +
		"/unmute — unmute alerts\n" +
		"/explain &lt;kind&gt; — explain an event kind\n" +
		"/help — this help",
	"ui.status": "<b>{host}</b>\n" +
		"Profile: {profile}\n" +
		"Uptime: {uptime}\n" +
		"Events in 24h: {events} (critical: {critical})\n" +
		"Last event: {last}\n" +
		"Allowlist: {allow}\n" +
		"Alerts: {muted}",
	"ui.last.header":      "Recent events ({count}):",
	"ui.last.empty":       "No events yet.",
	"ui.allow.ok":         "Address {ip} added to the allowlist and will not be banned.",
	"ui.allow.removed":    "Address {ip} removed from the allowlist.",
	"ui.allow.missing":    "Address {ip} is not in the allowlist.",
	"ui.allow.header":     "Allowlist ({count}):",
	"ui.allow.empty":      "The allowlist is empty.",
	"ui.ban.recorded":     "Ban decision for {ip} recorded. Applying bans on the host arrives in v0.2.",
	"ui.ban.allowlisted":  "Address {ip} is allowlisted, the ban was cancelled.",
	"ui.ban.header":       "Ban decisions ({count}):",
	"ui.ban.empty":        "No bans.",
	"ui.ban.removed":      "Ban on {ip} lifted.",
	"ui.ban.missing":      "There is no ban for {ip}.",
	"ui.mute.on":          "Alerts muted until {until}. Critical events still come through.",
	"ui.mute.off":         "Alerts unmuted.",
	"ui.grouped":          "Similar events in {window}: {count} more.",
	"ui.not_available":    "This capability arrives in a later version.",
	"ui.never":            "none",
	"val.unknown":         "unknown",
	"ui.muted_until":      "muted until {until}",
	"ui.not_muted":        "on",
	"ui.err.unknown_cmd":  "Unknown command. /help lists them.",
	"ui.err.need_arg":     "An argument is required. Example: {usage}",
	"ui.err.bad_ip":       "That does not look like an IP address: {value}",
	"ui.err.unknown_kind": "Unknown event kind: {kind}\nAvailable kinds: {kinds}",
}
