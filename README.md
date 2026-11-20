# ARDA CLI

Python command-line utilities for the ARDA Android Automotive project.

## Requirements

- Python 3.11 or later on macOS
- SSH access to a separately configured Ubuntu AOSP build host for remote commands
- Git and GitHub CLI for repository operations

## Installation

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install .
arda --help
```

Create `~/.config/arda/config.toml` before using remote commands. The defaults
in `arda_cli/config.py` are **examples**, not production addresses. Use an SSH
key with appropriate permissions and never commit your real config or keys.

## Safety

This utility includes advanced migration, build, deploy, and release commands.
Review each command before running it; some can modify repositories or devices.
The CLI is separate from the public ARDA image installer.

## Provenance and licensing

This public repository is a sanitized snapshot derived from the privately
maintained ARDA CLI V16.1. The earlier private Git history is **not** published.
Licensed under the Apache License 2.0; see LICENSE. Historical upstream-derived
code, if any, remains subject to its original rights and attribution.
