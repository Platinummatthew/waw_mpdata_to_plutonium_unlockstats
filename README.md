# World at War MPData to Plutonium Tools

Offline, source-available tools for transferring a Call of Duty: World at War PC multiplayer profile into the `unlockstats_mp` format used by Plutonium T4, plus an editor for raw `unlockstats_mp` files.

## Included tools

- **Offline HTML converter** — decrypts and validates an individual retail/Steam `mpdata` file in the browser. The user enters the matching World at War CD key manually.
- **Python converter** — supports individual files, profile folders, and ZIP archives. On Windows it can search the normal registry locations for the matching CD key.
- **Windows drag-and-drop launchers** — convenient wrappers for conversion and installation. Python 3.10 or newer must be installed.
- **Offline HTML editor** — reads and edits known fields in an existing `unlockstats_mp` file and recalculates its CRC-32 when saving.
- **Python raw-stat tool** — inspect, edit, repair, dump, and compare raw `unlockstats_mp` files.

The current import target used by the project is:

```text
%LOCALAPPDATA%\Plutonium\storage\t4\plutonium\unlockstats_mp
```

Custom class names do not transfer to Plutonium and must be renamed in-game after import.

## Requirements

### Browser tools

Open either HTML file in a current desktop browser. No installation, server, or internet connection is required.

### Python and batch tools

- Windows 10 or newer is recommended for registry lookup and the `.bat` launchers.
- Python **3.10 or newer** must be installed.
- No third-party Python packages are required.

Check Python with:

```bat
py -3 --version
```

## Quick start

### Convert with the HTML version

1. Open `waw_mpdata_to_unlockstats_mp.html`.
2. Select the Steam/retail `mpdata` file.
3. Enter the matching World at War CD key.
4. Confirm outer authentication and inner CRC validation.
5. Save the generated file as `unlockstats_mp`.

### Convert with the Windows launcher

1. Install Python 3.10 or newer.
2. Drag `mpdata`, `mpdatabk0000`, a profile folder, or a profile ZIP onto `convert_mpdata_drag_and_drop.bat`.
3. The converter searches the standard World at War registry locations for a matching CD key. It prompts only when no matching key is found.
4. Confirm the generated file is exactly 8,192 bytes and reports a valid CRC.

### Install the generated file

Drag `unlockstats_mp` onto `install_unlockstats_mp_drag_and_drop.bat`, or manually copy it to:

```text
%LOCALAPPDATA%\Plutonium\storage\t4\plutonium\unlockstats_mp
```

After selecting the intended Plutonium multiplayer profile, run `/unlockall` once. Back up both the Steam and Plutonium profiles before importing.

## Self-test

```bash
python waw_mpdata_transfer_tool.py self-test
python -m compileall -q waw_mpdata_transfer_tool.py waw_unlockstats_mp_tool.py
```

The self-test covers MD4 vectors, encryption/decryption round trips, CD-key normalization, wrong-key rejection, ASCII-hex input, and CRC handling.

## Repository safety

The tools run locally and contain no telemetry or network code. Do not commit or publish:

- World at War CD keys
- `mpdata` or `mpdatabk0000`
- `.corrupt` profile files
- generated `unlockstats_mp` files containing personal player data

See [SECURITY.md](SECURITY.md) for reporting and privacy guidance.

## Documentation

- [Quick start](docs/QUICK_START.txt)
- [Detailed usage and format notes](docs/DETAILED_USAGE.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)
- [Changelog](CHANGELOG.md)

## License

This project is licensed under the GNU General Public License, version 2 or later. See [LICENSE](LICENSE).

The IWM encryption/decryption implementation is a Python/JavaScript reimplementation informed by `codmpdatadec`, Copyright © 2009 Luigi Auriemma. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Disclaimer

This community project is not affiliated with, endorsed by, or sponsored by Activision, Treyarch, Steam, or Plutonium. Use it only with profile data and software you are authorized to access, and always keep backups.
