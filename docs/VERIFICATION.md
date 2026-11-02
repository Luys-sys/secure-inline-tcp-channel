# Reproducible verification

The following checks were run in the packaging environment:

- GCC compilation: standalone authenticated handshake
- Six existing crypto / packet transformation test targets: PASS
- Two real processes over loopback: signed X25519 + key-confirmation +
  cross-direction derived key and salt comparison: PASS

The live Netfilter Queue test requires Linux kernel network namespace,
iptables, libnetfilter_queue and WSL2/network privileges. Run
`sudo bash scripts/run_lab.sh` on the intended lab system. Treat a failing
exit status as a failing acceptance test. No successful live encrypted
packet forwarding is claimed in this verification record.
