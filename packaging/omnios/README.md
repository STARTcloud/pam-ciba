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

One entry per service in `/etc/pam.conf`, with `pam_unix_cred.so.1` above it for the credential step:

```text
service auth required pam_unix_cred.so.1
service auth required pam_ciba.so.1
```

The module runs `/opt/pam-ciba/pam-ciba authenticate`. A first option that is an absolute path names another program; further options are passed to the program before `authenticate`:

```text
service auth required pam_ciba.so.1 /opt/pam-ciba/pam-ciba --config /etc/pam-ciba
```

## Test

```bash
pfexec /opt/pam-ciba/pam-ciba check USER
```
