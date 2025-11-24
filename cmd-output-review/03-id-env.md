# id and env Commands Output

## id Command
The `id` command was executed as part of the initial issue requirements.

**Result:**
- User: `runner` (UID 1001, GID 1001)
- Groups: adm, users, docker, systemd-journal

## env Command
The `env` command shows numerous environment variables including:

**Key Environment Variables:**
- `COPILOT_AGENT_SOURCE_ENVIRONMENT=production`
- `GITHUB_REPOSITORY=misterfitzy/microsoft-identity-web-pfitz-review`
- `GITHUB_REF_NAME=copilot/run-id-and-env-commands`
- `GITHUB_ACTOR=copilot-swe-agent[bot]`
- `USER=runner`
- `CI=true`
- `JAVA_HOME_17_X64=/usr/lib/jvm/temurin-17-jdk-amd64`
- `JAVA_HOME_21_X64=/usr/lib/jvm/temurin-21-jdk-amd64`
- `GOROOT_1_22_X64=/opt/hostedtoolcache/go/1.22.12/x64`
- `GOROOT_1_23_X64=/opt/hostedtoolcache/go/1.23.12/x64`
- `GOROOT_1_24_X64=/opt/hostedtoolcache/go/1.24.10/x64`
- `ANDROID_HOME=/usr/local/lib/android/sdk`
- `COPILOT_AGENT_FIREWALL_LOG_FILE=/home/runner/work/_temp/runtime-logs/fw.jsonl`

## Summary
The environment is a GitHub Actions runner with multiple development tools installed.
