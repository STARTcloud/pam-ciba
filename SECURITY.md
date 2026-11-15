# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in PAM CIBA, please report it responsibly:

### Preferred Method: Security Advisory

1. Go to the [GitHub Security Advisory page](https://github.com/STARTcloud/pam-ciba/security/advisories)
2. Click "Report a vulnerability"
3. Fill out the advisory form with detailed information
4. Submit the advisory

### What to Include

Please provide as much information as possible:

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Potential impact** of the vulnerability
- **Affected versions** (if known)
- **Suggested fix** (if you have one)
- **Your contact information** for follow-up questions

## Response Process

Due to limited development resources, please understand that:

- **Initial Response**: We aim to acknowledge receipt within 48-72 hours
- **Assessment**: Initial assessment will be completed within 1 week
- **Resolution**: Timeline depends on severity and complexity, typically 1-4 weeks
- **Disclosure**: Coordinated disclosure after fix is available

### Severity Levels

- **Critical**: Immediate attention (RCE, privilege escalation)
- **High**: Quick response needed (authentication bypass, data exposure)
- **Medium**: Standard timeline (DoS, information disclosure)
- **Low**: Lower priority (minor information leaks)

## Security Considerations for PAM CIBA

PAM CIBA decides whether a sign-in is accepted, so please pay special attention to:

### High-Risk Areas

- **Sign-in decision**: Anything that accepts a sign-in without a verified ID token for the mapped account
- **Token validation**: Signature, issuer, audience, authorized party or expiry checks that can be bypassed
- **Provider trust**: Discovery or key retrieval over anything but verified https
- **File system operations**: Path traversal or unauthorized file access (config, logs)
- **PAM integration**: Stack lines or the illumos service module answering success where they must not

### Configuration Security

- **Default configurations**: Insecure defaults
- **User mapping**: A local account reaching a provider account it is not mapped to

## Best Practices for Users

To maintain security:

1. **Keep Updated**: Always run the latest release
2. **Protect your config directory**: It decides which provider account each local account signs in as
3. **Monitor Logs**: Watch for suspicious activity in the log file

## Security Tooling in CI

Every change runs through:

- **gosec** (via golangci-lint): Go security static analysis
- **govulncheck**: known-vulnerability scanning with call-graph reachability, on PRs and weekly
- **CodeQL**: GitHub code scanning for Go and workflow files
- **Dependabot**: dependency update automation

## Acknowledgments

We appreciate the security research community's efforts in making PAM CIBA more secure. Responsible disclosure helps protect all users.

### Hall of Fame

Contributors who responsibly report security vulnerabilities will be acknowledged here (with their permission):

- *No vulnerabilities reported yet*

## Updates to This Policy

This security policy may be updated as the project evolves. Check back periodically for changes.

---

**Remember**: Security is a shared responsibility. Your vigilance and responsible reporting help keep everyone safe.
