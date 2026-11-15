# Debian packaging

`prod-build.yml` builds `pam-ciba_<version>_amd64.deb` and publishes it to the STARTcloud Debian repository.

## Build

```bash
VERSION=0.1.0
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X github.com/STARTcloud/pam-ciba/internal/version.Version=${VERSION}" \
  -o bin/pam-ciba .
```

The workflow stages the files below, writes `DEBIAN/control` and runs `dpkg-deb --build --root-owner-group`.

## Installed files

| Path | What |
| --- | --- |
| `/usr/bin/pam-ciba` | The program |
| `/usr/share/pam-ciba/config/app.config.yaml` | The first-install configuration |
| `/etc/pam-ciba/app.config.yaml` | The configuration, written by `postinst` when absent, mode 600 |
| `/usr/share/man/man8/pam-ciba.8.gz` | `pam-ciba(8)` |
| `/usr/share/man/man5/pam-ciba.yaml.5.gz` | `pam-ciba.yaml(5)` |

The package depends on `libpam-modules` for `pam_exec` and `pam_permit`, and on `ca-certificates`.

## Maintainer scripts

| Script | What it does |
| --- | --- |
| `postinst` | Creates `/etc/pam-ciba` (mode 700, root) and seeds the configuration when absent |
| `prerm` | Warns when `/etc/pam.d` still names `pam-ciba` |
| `postrm` | Removes `/etc/pam-ciba` on purge |

## PAM configuration

```text
auth [success=ok ignore=ignore default=die] pam_exec.so quiet /usr/bin/pam-ciba authenticate
auth [success=done default=die] pam_permit.so
```

## Test

```bash
sudo pam-ciba check USER
```
