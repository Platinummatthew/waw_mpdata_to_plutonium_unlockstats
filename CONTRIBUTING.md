# Contributing

1. Do not include real your CD key, profile saves, generated player data, or any personal fingerprints.
2. Keep the browser tools offline and dependency-free unless a change is clearly documented and justified.
3. Run:

```bash
python waw_mpdata_transfer_tool.py self-test
python -m compileall -q waw_mpdata_transfer_tool.py waw_unlockstats_mp_tool.py
```

4. Test Windows batch-file changes on Windows when possible.
5. Update `README.md` and `CHANGELOG.md` when behavior or requirements change.

Code should remain readable and conservative around profile writes. Source files must never be overwritten during conversion, and installation changes must preserve the existing backup behavior.
