Their isnt really much left to add on to this project but if you want contribute

1. Do not include your real CD key, profile saves, generated player data, or any personal fingerprints.
2. Keep the browser tools offline and dependency-free unless a change is needed.
3. Run:

```bash
python waw_mpdata_transfer_tool.py self-test
python -m compileall -q waw_mpdata_transfer_tool.py waw_unlockstats_mp_tool.py
```

4. Test Windows batch-file changes on Windows when possible.
5. Update `README.md` and `CHANGELOG.md` when behavior or requirements change.

Code should remain readable and conservative around profile writes. Source files must never be overwritten during conversion, and installation changes must preserve the existing backup behavior.
