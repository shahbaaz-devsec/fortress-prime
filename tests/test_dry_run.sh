      - name: Prepare log directory
        run: sudo mkdir -p /var/log/fortress-prime && sudo chmod 777 /var/log/fortress-prime

      - name: Dry‑run smoke test (no root)
        run: python3 fortress_prime.py --dry-run --non-interactive --admin-user ci-test --ssh-port 2222

      - name: Clean up log directory
        run: sudo rm -rf /var/log/fortress-prime
