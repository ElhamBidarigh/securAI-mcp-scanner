# Security Policy

## Supported versions

Only the latest release receives fixes. This is a small, solo-maintained open source project, so there is no formal response time, but reports are read and answered as soon as possible.

## Reporting a vulnerability in this tool

Please do not open a public issue with exploit details.

1. Use GitHub's private reporting: open the **Security** tab of this repository and choose **Report a vulnerability**.
2. If that option is not available, open a public issue titled "Security contact request" that contains no technical details, and a private channel will be arranged.

Useful reports include the version (`mcp-trust-scanner --version`), the command you ran, what you expected, and what happened. Examples of in-scope problems: a crafted MCP config that makes the scanner execute code, read files it should not, or write outside the paths you gave it.

## Scope and safe use

- The scanner is a defensive tool. By default it only reads the config file you give it. The `--live` option starts the servers listed in that config, so use it only on configs you trust and are allowed to run.
- Detection is heuristic. A clean result is not proof that an MCP server is safe, and a finding is a lead for review, not a confirmed exploit.
- Only scan systems you own or have permission to test.
