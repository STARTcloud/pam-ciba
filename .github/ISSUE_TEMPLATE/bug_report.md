---
name: Bug report
about: Create a report to help us improve
title: '[BUG] '
labels: 'bug'
assignees: ''
---

## Bug Description

A clear and concise description of what the bug is.

## Environment

**System Information:**

- OS: [e.g., Debian 13, OmniOS r151059]
- PAM CIBA Version: [e.g., 0.1.0]
- Installation Method: [package/source]
- OpenID Provider: [e.g., name and version]

**Configuration:**

- PAM service: [e.g., sshd]
- PAM lines: [the pam-ciba lines of the stack]

## Steps to Reproduce

Steps to reproduce the behavior:

1. Go to '...'
2. Run '...'
3. See error

## Expected Behavior

A clear and concise description of what you expected to happen.

## Actual Behavior

A clear and concise description of what actually happened.

## Error Messages / Logs

If applicable, add error messages or log excerpts (the agent log lives at `<config dir>/logs/agent.log`):

```text
Paste error messages here
```

## API Requests (if applicable)

**Request:**

```bash
sudo pam-ciba check USER
```

**Response:**

```json
{
  "error": "Error details here"
}
```

## Additional Context

Add any other context about the problem here.

## Impact Assessment

- [ ] Critical (system unusable, security issue)
- [ ] High (major functionality broken)
- [ ] Medium (functionality impaired)
- [ ] Low (minor issue, workaround available)

**Affected Functionality:**

- [ ] Sign-in flow
- [ ] Pool collection
- [ ] API endpoints
- [ ] Authentication
- [ ] Configuration
- [ ] Logging
- [ ] Packaging
- [ ] Documentation

## Resource Understanding

I understand that this project is maintained with limited development resources and that:

- Response times may vary based on current workload and severity
- Critical and high-impact issues receive priority attention
- Detailed bug reports help prioritize and resolve issues more efficiently
