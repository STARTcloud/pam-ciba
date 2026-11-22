# OmniOS packaging

`build.sh` builds the IPS package `system/security/pam-ciba` on an OmniOS host: the Go program, and the PAM service module `pam_ciba.so.1` compiled from `pam_ciba.c`. illumos PAM has no `pam_exec`, so the module runs the program.

## Requirements

- Go (the `go` line of `go.mod`)
- `gcc`
- The IPS tools `pkgsend`, `pkgfmt`, `pkgmogrify`, `pkgrepo`, `pkgrecv`

## Build

```bash
export PATH=/opt/ooce/bin:$PATH
export VERSION=0.1.0
./packaging/omnios/build.sh
```

The result is `pam-ciba-${VERSION}.p5p`.

## Installed files

| Path | What |
| --- | --- |
| `/opt/pam-ciba/pam-ciba` | The program |
| `/usr/lib/security/amd64/pam_ciba.so.1` | The PAM service module |
| `/etc/pam-ciba/app.config.yaml` | The configuration, preserved across upgrades |
| `/var/log/pam-ciba/pam-ciba.log` | The log, rotated by the program |
| `/opt/ooce/share/man` | `pam-ciba(8)`, `pam-ciba.yaml(5)` |

## PAM configuration

One `binding` entry per service in `/etc/pam.conf`, above the password lines of the stock `other` stack. A mapped account whose sign-in is approved ends the stack there and is asked nothing; a mapped account whose sign-in is refused fails the stack; an account with no entry under `users` is skipped and signs in by its password:

```text
sshd auth binding   pam_ciba.so.1
sshd auth requisite pam_authtok_get.so.1
sshd auth required  pam_dhkeys.so.1
sshd auth required  pam_unix_cred.so.1
sshd auth required  pam_unix_auth.so.1
```

The module runs `/opt/pam-ciba/pam-ciba authenticate` and returns `PAM_SUCCESS` on exit 0, `PAM_IGNORE` on exit 2 (no entry under `users`) and `PAM_AUTH_ERR` otherwise. A first option that is an absolute path names another program; further options are passed to the program before `authenticate`:

```text
sshd auth binding pam_ciba.so.1 /opt/pam-ciba/pam-ciba --config /etc/pam-ciba
```

## Test

```bash
pfexec /opt/pam-ciba/pam-ciba check USER
```
