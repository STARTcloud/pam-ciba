# PAM CIBA

**PAM CIBA** signs a local account in through an OpenID Provider's push approval: [OpenID Connect Client-Initiated Backchannel Authentication Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) in poll mode. It is a single Go binary that `pam_exec` runs in a PAM auth stack.

The person signing in is asked nothing in the terminal. The provider notifies the mapped end-user on their own device, the end-user approves there, and the sign-in completes. A sign-in is accepted only when the provider issues an ID token that verifies and names the mapped account.

## Getting started

Debian, from the STARTcloud repository:

```bash
sudo apt install pam-ciba
```

Set the provider and the accounts in `/etc/pam-ciba/app.config.yaml`:

```yaml
schemaVersion: 1
provider:
  issuer: https://auth.example.org
  client_id: host-ssh
users:
  alice: alice@example.org
```

Test a sign-in; it prints each step and exits 0 once the end-user approves:

```bash
sudo pam-ciba check alice
```

## Provider

The provider publishes OpenID Connect Discovery metadata with a `backchannel_authentication_endpoint` and `poll` among its `backchannel_token_delivery_modes_supported`.

The client is public (no secret), holds the grant type `urn:openid:params:grant-type:ciba` with poll delivery, and is granted the configured scope, which contains `openid`.

## PAM configuration

Two lines in the service's auth stack, above the lines they replace:

```text
auth [success=ok ignore=ignore default=die] pam_exec.so quiet /usr/bin/pam-ciba authenticate
auth [success=done default=die] pam_permit.so
```

The first line runs the sign-in and ends the stack on any failure. The second line ends the stack on success and answers the credential step, which `pam_exec` leaves unanswered.

For OpenSSH, `sshd_config` needs:

```text
UsePAM yes
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
LoginGraceTime 6m
```

`LoginGraceTime` is longer than the provider's request lifetime, so the end-user has the whole lifetime to approve.

## Configuration

The configuration is one file, `app.config.yaml`, read from `/etc/pam-ciba`. `--config <dir>` or `CONFIG_DIR` names another directory.

Every key takes its default from the schema in `internal/config/schema/app.schema.yaml`.

| Key | Meaning |
| --- | --- |
| `provider.issuer` | The provider's issuer identifier, an https URL |
| `provider.client_id` | The public client registered for CIBA poll delivery |
| `provider.scope` | Scope of the request; contains `openid` (default `openid profile`) |
| `provider.request_timeout_seconds` | Bound on each HTTP request to the provider (default 10) |
| `approval.binding_message` | Shown to the end-user beside the approval; `{user}`, `{host}`, `{rhost}` and `{service}` are replaced; sent only while `approval.authorization_details_type` is empty |
| `approval.requested_expiry_seconds` | Request lifetime asked of the provider; 0 takes the provider's default |
| `approval.authorization_details_type` | The RFC 9396 authorization details type registered at the provider for this client; when set, the request carries one detail of that type with the fields `user`, `host` (the full host name), `remote_host` (the login session's remote host when PAM names none), `remote_user`, `tty` (left out when it is `ssh`), `service`, `command` (the command line of a `sudo` request) and `at`, a field with no value left out |
| `users` | Local account name to the provider account it signs in as; an account without an entry is refused |
| `logging` | Level, file, rotation |

Commands: `authenticate` (run by `pam_exec`; reads `PAM_USER`, `PAM_RHOST`, `PAM_RUSER`, `PAM_TTY`, `PAM_SERVICE`), `check USER`, `--version`.

## Building from source

Requires Go 1.26 (the `go` line of `go.mod`).

```bash
go mod tidy
go build -o pam-ciba .
```

Packaging: [packaging/DEBIAN/README.md](packaging/DEBIAN/README.md).

## Contributing

Contributions welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GPL-3.0, see [LICENSE.md](LICENSE.md).
