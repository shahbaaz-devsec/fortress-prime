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
