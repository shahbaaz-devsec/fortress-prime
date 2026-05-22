      - name: Dry-run smoke test (no root)
        run: python3 fortress_prime.py --dry-run --non-interactive --admin-user ci-test --ssh-port 2222
