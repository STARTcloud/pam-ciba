// PAM CIBA signs a local account in through an OpenID Provider's
// Client-Initiated Backchannel Authentication flow in poll mode. pam_exec runs
// it in a PAM auth stack: it asks the provider to have the mapped end-user
// approve the sign-in on their own device, waits for the answer and exits 0
// when the provider issues an ID token for that end-user. It asks the terminal
// nothing.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
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
			localUser: os.Getenv("PAM_USER"),
			remote:    os.Getenv("PAM_RHOST"),
			service:   os.Getenv("PAM_SERVICE"),
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
	if aerr := authenticate(ctx, cfg, login, progress); aerr != nil {
		log.Warn("sign-in refused", "reason", aerr.Error())
		return aerr
	}
	log.Info("sign-in approved")
	return nil
}

type signIn struct {
	localUser string
	remote    string
	service   string
}

// authenticate runs one CIBA sign-in for login and answers nil only when the provider issues a verified ID token for the provider account the local account maps to.
func authenticate(ctx context.Context, cfg *config.Config, login signIn, progress io.Writer) error {
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

	client := &ciba.Client{HTTP: httpClient, Metadata: metadata, ClientID: cfg.Provider.ClientID}
	request, err := client.Authorize(ctx, cfg.Provider.Scope, account,
		bindingMessage(cfg.Approval.BindingMessage, login), cfg.Approval.RequestedExpirySeconds)
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

// bindingMessage fills the template's placeholders and answers at most 255 printable characters, the binding_message a provider shows the end-user.
func bindingMessage(template string, login signIn) string {
	host, err := os.Hostname()
	if err != nil {
		host = "this host"
	}
	remote := login.remote
	if remote == "" {
		remote = "the console"
	}
	message := strings.NewReplacer(
		"{user}", login.localUser,
		"{host}", host,
		"{rhost}", remote,
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
