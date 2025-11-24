# env Command Output

```bash
runner@github-runner:~$ env
COPILOT_AGENT_SOURCE_ENVIRONMENT=production
JAVA_HOME_21_X64=/usr/lib/jvm/temurin-21-jdk-amd64
COPILOT_AGENT_ACTION=fix-pr-comment
GITHUB_ENV=/home/runner/work/_temp/_runner_file_commands/set_env_00208878-41fb-4eb7-bb1e-cab2b4c2d9be
GITHUB_EVENT_PATH=/home/runner/work/_temp/_github_workflow/event.json
INVOCATION_ID=8e1ce22195d7488ba50700b4477008d3
GITHUB_EVENT_NAME=dynamic
GITHUB_RUN_ID=19616796778
JAVA_HOME_17_X64=/usr/lib/jvm/temurin-17-jdk-amd64
COPILOT_AGENT_COMMIT_EMAIL=198982749+Copilot@users.noreply.github.com
ANDROID_NDK_HOME=/usr/local/lib/android/sdk/ndk/27.3.13750724
GITHUB_STEP_SUMMARY=/home/runner/work/_temp/_runner_file_commands/step_summary_00208878-41fb-4eb7-bb1e-cab2b4c2d9be
HOMEBREW_NO_AUTO_UPDATE=1
GITHUB_ACTOR=copilot-swe-agent[bot]
COPILOT_AGENT_FIREWALL_LOG_FILE=/home/runner/work/_temp/runtime-logs/fw.jsonl
COPILOT_USE_SESSIONS=true
NVM_DIR=/home/runner/.nvm
...
```

## Key Environment Variables

### GitHub Context
- `GITHUB_REPOSITORY=misterfitzy/microsoft-identity-web-pfitz-review`
- `GITHUB_REF_NAME=copilot/run-id-and-env-commands`
- `GITHUB_BASE_REF=master`
- `GITHUB_ACTOR=copilot-swe-agent[bot]`
- `GITHUB_RUN_ID=19616796778`

### Development Tools
- Java 17: `/usr/lib/jvm/temurin-17-jdk-amd64`
- Java 21: `/usr/lib/jvm/temurin-21-jdk-amd64`
- Go 1.22: `/opt/hostedtoolcache/go/1.22.12/x64`
- Go 1.23: `/opt/hostedtoolcache/go/1.23.12/x64`
- Go 1.24: `/opt/hostedtoolcache/go/1.24.10/x64`
- Android SDK: `/usr/local/lib/android/sdk`

### Copilot Agent
- `COPILOT_AGENT_SOURCE_ENVIRONMENT=production`
- `COPILOT_AGENT_ACTION=fix-pr-comment`
- `COPILOT_MCP_ENABLED=true`
- `COPILOT_USE_SESSIONS=true`
