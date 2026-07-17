I could not find the old Easy Account Manager tool to help me transfer my Steam MP profile, so i took matters into my own hands.

These tools will help you transfer your World at War multiplayer profile from the Steam/Retail version into Plutonium T4.

The **MPData Converter** reads the encrypted `mpdata` file, authenticates it using the matching World at War CD key, extracts the complete multiplayer statistics block, verifies its checksum, and generates an `unlockstats_mp` file.

That generated file can then be placed in:

```text
%LOCALAPPDATA%\Plutonium\storage\t4\plutonium\
```

and imported into your active Plutonium profile using `/unlockall`.

This package includes two converter options:

* An offline HTML version that runs directly in a web browser, does not require Python, and requires the CD key to be entered manually.
* A Windows batch/Python version that can automatically locate the installed World at War CD key in the Windows Registry and verify it against the selected profile.

**Python 3 must be installed to use the `.bat` files and the included Python command-line tool.** The HTML converter and HTML Unlockstats Editor **do not** require Python.

The converter transfers the entire multiplayer statistics block, including rank, prestige, XP, combat statistics, challenges, weapon unlocks, perks, attachments, and custom-class loadout data (Custom-class names do not transfer, they will need to be entered again).

Also included is an **Unlockstats Editor**  that can open an existing `unlockstats_mp` file. It displays player statistics, allows values to be edited and automatically regenerates the required CRC-32 checksum when saving. It runs locally in a web browser and does not require Python.

Your Steam/Retail key is located at:

```text
"Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Activision\Call of Duty WAW"
```
