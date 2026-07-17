# Security and Privacy

## Sensitive files

Never attach or commit a World at War CD key. Do not publish retail or Plutonium profile files unless you have deliberately removed all private player data.

The repository `.gitignore` excludes common sensitive inputs and outputs, including:

- `mpdata`
- `mpdatabk*`
- `*.corrupt`
- `unlockstats_mp`
- common private key text files

Git can still track an ignored file if it was added previously. Before pushing, review staged content with:

```bash
git status
git diff --cached
```

## Local behavior

The HTML tools are designed to run entirely in the browser and make no network requests. The Python converter uses the standard library only. On Windows, registry access is read-only and is used to locate a matching installed World at War CD key.

The full CD key should never be printed, written to output files, or included in logs. Command-line `--cd-key` input is supported but is less private because shell history and process listings can expose arguments; registry lookup, hidden prompts, or `--key-file` are safer.

## Reporting a vulnerability

Do not include real CD keys or save files in a public issue. Describe the problem with synthetic data or privately contact the repository maintainer using the security contact configured for the GitHub repository.
