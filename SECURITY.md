# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/domehahn/rantanplan/security/advisories/new).
Include the version (`rantanplan --version` / git tag), what you observed and a minimal reproduction.
You can expect an acknowledgement within a week.

Supported versions: the latest release on `main`. This is pre-1.0 software.

## What counts as a vulnerability here

Rantanplan feeds attack-shaped text to third-party scanners and runs their binaries. Relevant issues include
sandbox escapes or secret leakage into scanner subprocesses, a corpus or report path that executes fixture
content, and unsafe handling of untrusted scanner output.

## Safety boundaries

1. **Fixtures are inert data.** Dangerous-looking strings (`rm -rf /`, `requests.post(url, data=os.environ)`)
   are only written to temporary files for the scanner to read. Rantanplan never executes fixture content.
2. **No real credentials.** Fixtures use dummy values only. Scanner subprocesses receive a whitelisted
   environment (`PATH`, a temporary `HOME`, locale) so host secrets are not passed on (covered by tests).
3. **Subprocess isolation.** Scanners run with `shell=False`, a wall-clock timeout, and their own process
   group, which is killed as a whole on timeout. There is no memory limit and no container or seccomp
   isolation: **run untrusted scanner binaries in a container or VM.**
4. **Offline by default.** The calibration suite and the corpus need no network. Real scanners you install
   may use the network; Rantanplan does not control that.
5. **Reports escape dynamic text** (HTML) and never include environment variables.

See also [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
