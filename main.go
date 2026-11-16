// PAM CIBA signs a local account in through an OpenID Provider's
// Client-Initiated Backchannel Authentication flow in poll mode. pam_exec runs
// it in a PAM auth stack: it asks the provider to have the mapped end-user
// approve the sign-in on their own device, waits for the answer and exits 0
// when the provider issues an ID token for that end-user. It asks the terminal
// nothing.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/STARTcloud/pam-ciba/internal/ciba"
	"github.com/STARTcloud/pam-ciba/internal/config"
	"github.com/STARTcloud/pam-ciba/internal/logging"
	"github.com/STARTcloud/pam-ciba/internal/oidc"
	"github.com/STARTcloud/pam-ciba/internal/version"
)

const usage = `usage:
  pam-ciba [--config DIR] authenticate    sign in the account named by PAM_USER; run by pam_exec
  pam-ciba [--config DIR] check USER      sign in USER and print each step
  pam-ciba --version                      print the version`

const maxBindingMessageLength = 255

const (
	hostLookupTimeout = 2 * time.Second
	sshTTY            = "ssh"
)

// main stays defer-free so os.Exit cannot skip cleanup; all work and all
// defers live in run.
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	configDir := flag.String("config", "", "configuration directory (default: CONFIG_DIR, else "+config.SystemDir+")")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() { fmt.Fprintln(os.Stderr, usage) }
	flag.Parse()

	if *showVersion {
		fmt.Fprintln(os.Stdout, version.Version)
		return nil
	}

	var login signIn
	progress := io.Discard
	switch {
	case flag.NArg() == 1 && flag.Arg(0) == "authenticate":
		if pamType := os.Getenv("PAM_TYPE"); pamType != "" && pamType != "auth" {
			return fmt.Errorf("pam-ciba authenticate runs in the auth stack, not %s", pamType)
		}
		login = signIn{
			localUser:  os.Getenv("PAM_USER"),
			remote:     os.Getenv("PAM_RHOST"),
			remoteUser: os.Getenv("PAM_RUSER"),
			tty:        os.Getenv("PAM_TTY"),
			service:    os.Getenv("PAM_SERVICE"),
		}
	case flag.NArg() == 2 && flag.Arg(0) == "check":
		login = signIn{localUser: flag.Arg(1), service: "check"}
		progress = os.Stdout
	default:
		return errors.New(usage)
	}
	if login.localUser == "" {
		return errors.New("no account to sign in: PAM_USER is empty")
	}

	cfg, err := config.Load(config.Options{Dir: *configDir, Seed: true})
	if err != nil {
		return err
	}
	closeLog, err := logging.Setup(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closeLog(); cerr != nil {
			fmt.Fprintln(os.Stderr, cerr)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	log := logging.Category("auth").With("user", login.localUser, "rhost", login.remote, "service", login.service)
	if aerr := authenticate(ctx, cfg, &login, progress); aerr != nil {
		log.Warn("sign-in refused", "reason", aerr.Error())
		return aerr
	}
	log.Info("sign-in approved")
	return nil
}

type signIn struct {
	localUser  string
	remote     string
	remoteUser string
	tty        string
	service    string
}

type signInDetail struct {
	Type       string `json:"type"`
	User       string `json:"user,omitempty"`
	Host       string `json:"host,omitempty"`
	RemoteHost string `json:"remote_host,omitempty"`
	RemoteUser string `json:"remote_user,omitempty"`
	TTY        string `json:"tty,omitempty"`
	Service    string `json:"service,omitempty"`
	At         string `json:"at"`
}

// authenticate runs one CIBA sign-in for login and answers nil only when the provider issues a verified ID token for the provider account the local account maps to.
func authenticate(ctx context.Context, cfg *config.Config, login *signIn, progress io.Writer) error {
	if cfg.Provider.Issuer == "" || cfg.Provider.ClientID == "" {
		return errors.New("provider.issuer and provider.client_id are not configured")
	}
	account, mapped := cfg.LoginHint(login.localUser)
	if !mapped {
		return fmt.Errorf("local account %q has no entry under users", login.localUser)
	}

	httpClient := &http.Client{Timeout: time.Duration(cfg.Provider.RequestTimeoutSeconds) * time.Second}
	metadata, err := oidc.Discover(ctx, httpClient, cfg.Provider.Issuer)
	if err != nil {
		return err
	}
	keys, err := oidc.FetchKeys(ctx, httpClient, metadata.JWKSURI)
	if err != nil {
		return err
	}

	details, err := authorizationDetails(ctx, cfg.Approval.AuthorizationDetailsType, login, time.Now())
	if err != nil {
		return err
	}
	message := ""
	if details == "" {
		message = bindingMessage(cfg.Approval.BindingMessage, login)
	}
	client := &ciba.Client{HTTP: httpClient, Metadata: metadata, ClientID: cfg.Provider.ClientID}
	request, err := client.Authorize(ctx, cfg.Provider.Scope, account,
		message, details, cfg.Approval.RequestedExpirySeconds)
	if err != nil {
		return err
	}
	slog.Info("approval requested", "category", "auth", "user", login.localUser, "account", account,
		"expires_in", request.ExpiresIn.String(), "interval", request.Interval.String())
	fmt.Fprintf(progress, "approval requested from %s, waiting up to %s\n", account, request.ExpiresIn)

	tokens, err := client.Poll(ctx, request)
	if err != nil {
		return err
	}
	if tokens.IDToken == "" {
		return errors.New("provider issued no ID token")
	}
	claims, err := oidc.VerifyIDToken(tokens.IDToken, keys, metadata.Issuer, cfg.Provider.ClientID, time.Now())
	if err != nil {
		return err
	}
	if !claims.Identifies(account) {
		return fmt.Errorf("ID token is for %q, not the mapped account %q", claims.Subject, account)
	}
	fmt.Fprintf(progress, "approved by %s\n", claims.Subject)
	return nil
}

// authorizationDetails answers the RFC 9396 authorization_details array for login: one detail of detailType with the fields user, host (the full host name when the host has one), remote_host, remote_user, tty (left out when it is "ssh"), service and at, the RFC 3339 UTC time of now, a field with no value left out, or the empty string when detailType is empty.
func authorizationDetails(ctx context.Context, detailType string, login *signIn, now time.Time) (string, error) {
	if detailType == "" {
		return "", nil
	}
	tty := login.tty
	if tty == sshTTY {
		tty = ""
	}
	raw, err := json.Marshal([]signInDetail{{
		Type:       detailType,
		User:       login.localUser,
		Host:       fullHostName(ctx),
		RemoteHost: login.remote,
		RemoteUser: login.remoteUser,
		TTY:        tty,
		Service:    login.service,
		At:         now.UTC().Format(time.RFC3339),
	}})
	if err != nil {
		return "", fmt.Errorf("encode authorization details: %w", err)
	}
	return string(raw), nil
}

// fullHostName answers this host's fully qualified name: the host name when it holds a dot, else the canonical name the resolver answers for it, else the host name as it is, and the empty string when the host has no name.
func fullHostName(ctx context.Context) string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	if strings.Contains(host, ".") {
		return host
	}
	lookup, cancel := context.WithTimeout(ctx, hostLookupTimeout)
	defer cancel()
	canonical, err := net.DefaultResolver.LookupCNAME(lookup, host)
	if err != nil {
		return host
	}
	canonical = strings.TrimSuffix(canonical, ".")
	if strings.Contains(canonical, ".") {
		return canonical
	}
	return host
}

func hostName() string {
	host, err := os.Hostname()
	if err != nil {
		return "this host"
	}
	return host
}

func remoteName(login *signIn) string {
	if login.remote == "" {
		return "the console"
	}
	return login.remote
}

// bindingMessage fills the template's placeholders and answers at most 255 printable characters, the binding_message a provider shows the end-user.
func bindingMessage(template string, login *signIn) string {
	message := strings.NewReplacer(
		"{user}", login.localUser,
		"{host}", hostName(),
		"{rhost}", remoteName(login),
		"{service}", login.service,
	).Replace(template)
	printable := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, message)
	runes := []rune(strings.TrimSpace(printable))
	if len(runes) > maxBindingMessageLength {
		runes = runes[:maxBindingMessageLength]
	}
	return string(runes)
}
