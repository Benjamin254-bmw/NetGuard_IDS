# ADR 0014: Authentication failures come from the sshd log
Status: accepted.

Failed logins are invisible in network metadata (the exchange is encrypted), so `auth_failures`
reads the sshd authentication log (`NETGUARD_AUTH_LOG_PATH`, e.g. `/var/log/auth.log`).

- The tailer **starts at the end** of the file: history is not an attack in progress.
- It survives rotation (new inode), truncation, and in-place rewrite (64-byte head fingerprint),
  buffers partial lines, reads at most 1 MiB per poll, ignores lines over 4 KiB.
- A missing file is reported (`auth_log_unavailable` degraded reason) and read **from its start** when
  it appears. The monitor keeps running.
- Only the source IPv4 address and a read-time timestamp are kept. Usernames are discarded.
- Two line shapes are accepted: syslog style (`... sshd[123]: Failed password for X from IP port N`)
  and the **bare** shape a real `sshd -E <file>` writes (`Failed password for X from IP port N`).
  The bare shape was found by running a real sshd in the lab; the first parser (syslog only)
  silently saw nothing. The bare form must start the line so other programs' messages are ignored.
- The monitor user needs read access to the log (group `adm` on Debian/Kali for `/var/log/auth.log`).
  Read access to an authentication log is a privilege; grant it deliberately, to the monitor user only.

Time of detection is the time the monitor *read* the line (poll interval 0.5 s), not the time sshd
wrote it; latency figures for this rule include that delay.
