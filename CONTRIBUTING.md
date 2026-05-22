# Contributing to FORTRESS PRIME

Thank you for considering a contribution! This document explains how to report
bugs, propose features, and submit code changes.

## Code of Conduct

All contributors are expected to follow the
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Be respectful, constructive, and patient.

## How to Report a Bug

1. **Check existing issues** – search the [issue tracker](../../issues) to see if the bug has already been reported.
2. If not, **open a new issue** and include:
   - Your Ubuntu version (`lsb_release -a`)
   - The FORTRESS PRIME version (`fortress_prime.py --version`)
   - The exact command you ran
   - The full error output (redact sensitive information)
   - A description of what you expected to happen

> For **security vulnerabilities**, do **not** open a public issue. Follow the
> [Security Policy](SECURITY.md) instead.

## How to Propose a Feature

1. Open an issue with the **"enhancement"** label.
2. Describe the hardening control you want to add, including:
   - Which CIS / STIG / NIST section it addresses
   - Why it cannot be achieved by simply running the script with different flags
   - Whether it is automatable or requires manual review

We are particularly interested in controls that are **idempotent**, **verifiable**,
and do not break common production workloads.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/shahbaaz-devsec/fortress-prime.git
cd fortress-prime

# (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# The script has no external dependencies – you're ready to edit.
```

## Coding Standards

- The entire tool is a **single Python file**. Keep it that way.
- Follow **PEP 8**. Use 4 spaces for indentation.
- All new steps must have a **paired verifier** function.
- Every step must be **idempotent** – running it twice must converge to the same state.
- Use the existing `StepResult`, `FileManager`, and `Hardener` patterns.
- Comments explain **why**, not what the code does.
- Do **not** hardcode secrets, IPs, or credentials.

## Testing Your Changes

Always test on a **fresh Ubuntu 24.04 LTS VM** (use multipass, VirtualBox, or a cloud instance).

```bash
# 1. Syntax check
python3 -m py_compile fortress_prime.py

# 2. Dry‑run (no root needed for the first check)
python3 fortress_prime.py --dry-run --non-interactive

# 3. Apply on a test VM
sudo ./fortress_prime.py --admin-user test --ssh-port 2222 \
    --allow-from 0.0.0.0/0 --hostname test-vm --non-interactive

# 4. Verify posture
sudo ./fortress_prime.py --verify --admin-user test --ssh-port 2222 --non-interactive

# 5. Idempotency check: run again and confirm no unexpected changes
sudo ./fortress_prime.py --admin-user test --ssh-port 2222 \
    --allow-from 0.0.0.0/0 --non-interactive
```

## Pull Request Process

1. **Fork** the repository and create a new branch.
2. Make your changes in a **focused, minimal commit**.
3. Update `CHANGELOG.md` with a brief description of your change.
4. Submit a pull request to the `main` branch.
5. In the PR description, explain:
   - What the change does
   - Which compliance framework it addresses (if applicable)
   - How you tested it (include VM details)
6. A maintainer will review within a few days. We may ask for changes.

## What We Will Not Merge

- Code that disables core security features without an opt‑in flag
- Controls that cannot be verified automatically
- Controls that assume a specific non‑default environment (e.g., "disable IPv6" as default)
- Code that adds external Python dependencies
- Large refactors that do not address a specific issue

## Acknowledgements

Contributors will be listed in the repository's `README.md` or a dedicated
`AUTHORS.md` file. Please include your name and (optionally) a GitHub or
LinkedIn link in your PR.

---

*Thank you for helping make Ubuntu servers safer.*
