# WalletFinder - Scanning for Wallet Files and Mnemonic Phrases

`walletfinder.py` is a utility script included with BTCRecover that helps you locate wallet files and mnemonic seed phrases hidden in directories on your computer. It has two scanning modes: **Wallet Mode** (auto-detects supported wallet file formats) and **Mnemonic Mode** (scans text files and documents for BIP39, SLIP39, Electrum Legacy, or Blockchain wordlist words, plus private keys).

**By default `walletfinder.py` runs *both* modes** — in a single pass over the directory it scans each file for wallet formats *and* for seed phrases/private keys (each file is read at most once). Use `--skip-text-mode` to scan for wallet files only, or `--skip-wallet-mode` to scan text/documents only.

## Installation

`walletfinder.py` is included in the BTCRecover repository root. BTCRecover is **not** a pip package — you use it by [downloading and unzipping the repository](../INSTALL.md) (there is no `pip install btcrecover`), then running the scripts directly with Python. See the [main installation guide](../INSTALL.md) for setting up Python itself.

A dedicated requirements file for the script is included:

```
pip3 install -r requirements-walletfinder.txt
```

For **Wallet Mode** to be able to detect *and load every wallet type BTCRecover supports*, `walletfinder.py` needs the full BTCRecover dependency set, so `requirements-walletfinder.txt` pulls in `requirements-full.txt` (this is a larger, slower build). It also installs `shamir-mnemonic`, which **Mnemonic Mode** uses for SLIP39 seed-phrase detection.

If you get an error similar to **error: externally-managed-environment**, add `--break-system-packages` to the command (i.e. `pip3 install -r requirements-walletfinder.txt --break-system-packages`).

**Lightweight alternative (common wallets only):** if you only care about the common wallet types (Bitcoin Core, Blockchain.com, Electrum, MultiBit, MetaMask, …) plus Mnemonic Mode, `requirements-walletfinder.txt` contains a commented-out minimal subset (just `coincurve`, `protobuf`, `pycryptodome`, and `shamir-mnemonic`). Comment out the `-r requirements-full.txt` line and uncomment that subset for a much smaller/faster install. Note that some wallet types (e.g. certain Ethereum keystores, SLIP39 device wallets, and various altcoin wallets) may then be skipped in Wallet Mode.

Once the requirements are installed, run the script with Python from the repository root, for example:

```
python walletfinder.py --folder /path/to/search
```

### Optional: Document Scanning (Mnemonic Mode)

Mnemonic Mode scans **plain-text files out of the box** with no extra dependencies. To also extract and scan text from binary document formats — `docx`, `pdf`, `xlsx`, `pptx`, `odt`, `rtf`, `epub`, and similar — install [`textract`](https://pypi.org/project/textract/) **and** [`pypdf`](https://pypi.org/project/pypdf/) (ideally both):

```
pip3 install textract pypdf
```

With `textract` installed, Mnemonic Mode will look for seed phrases and private keys inside those document formats as well. Without it, only plain-text files are scanned and the script prints a one-time warning noting that document support is limited. Note that `textract` has heavy build dependencies and can be tricky to install on some platforms, which is why it is kept separate from `requirements-walletfinder.txt`.

`pypdf` is a lightweight extra used as a **PDF fallback**: some PDFs (e.g. paper wallets that use custom font encodings) extract as garbled single characters under `textract`'s `pdfminer` engine, and `pypdf` recovers the text in those cases. It also lets PDFs be scanned when `textract` itself could not be installed. The script prints a one-time warning if either package is missing, so installing both alongside each other is recommended.

## Default: Scan Both Modes

Running the script with no mode flag scans for **both** wallet files and seed phrases/private keys in a **single pass** over the directory — the tree is walked once and each file is read at most once, then handed to both detectors:

```
python walletfinder.py --folder /path/to/search
```

The output is split into two sections, `=== Wallet file scan ===` followed by `=== Text / seed-phrase & private-key scan ===`. To run just one mode, add `--skip-text-mode` (wallet files only) or `--skip-wallet-mode` (text/documents only) as shown below. (Because the two modes use different file-size limits — 64 MiB for wallet files, 16 KB for text — a given file may be scanned by one mode and not the other.)

### About the Progress Display

While scanning, `walletfinder.py` shows a single, continuously-updating status line with a spinner, a progress bar, and the directory/file currently being checked. To keep that line on one row in the terminal, long paths are **abbreviated for display only**:

- Paths up to 60 characters are shown in full.
- Longer paths have each folder/file name shortened to its first 3 and last 3 characters joined by `..` (for example `Documents` → `Doc..nts`).
- If the path is still very long after that, every component is shortened aggressively to its first and last character joined by a single `.` (for example `Documents` → `D.s`), producing lines like `C.\U.s\y.y\O.C\Y.e\...`.

This truncation is purely cosmetic — it only affects the live progress line. It does **not** change which files are scanned, and the **full, untruncated paths** are always used in the final results and summary.

### Saving Output to a File (Redirected Output)

For large scans (e.g. a whole drive) it's usually best to save the report to a file. `walletfinder.py` detects when its output is redirected (i.e. stdout is not a terminal) and automatically switches off the in-place status line — instead it prints one plain progress line per 10,000 items, so the report file stays small and readable rather than filling up with thousands of status-bar rewrites:

```
python walletfinder.py --folder /path/to/search > scan-report.txt 2>&1
```

The `2>&1` also captures any warnings sent to stderr. In a redirected run, progress appears as occasional plain lines like `Discovering... 20000 dirs` and `Scanned 640000/854101 candidates...` instead of the animated bar, and the full results and summary are written at the end exactly as normal.

While the scan is running, you can watch the report grow **live** from a second terminal:

**Linux and macOS:**
```
tail -f scan-report.txt
```

**Windows (PowerShell):**
```
Get-Content scan-report.txt -Wait -Tail 20
```

Both commands follow the file and print new lines as they are written (progress lines are flushed immediately for this purpose); press Ctrl+C to stop watching — the scan itself is unaffected. The same detection also means output piped to another program (e.g. `| tee scan-report.txt` on Linux/macOS, which shows *and* saves the output at the same time) gets the clean line-based progress instead of the status bar.

## Wallet Mode

Wallet mode uses BTCRecover's built-in wallet auto-detection to scan a directory recursively for supported wallet files. It reports each detected file with its type and confidence level. Use `--skip-text-mode` to scan for wallet files *only*.

### Basic Usage

Scan a single folder for wallet files only:
```
python walletfinder.py --folder /path/to/search --skip-text-mode
```

Limit recursion depth (e.g., only 2 levels deep):
```
python walletfinder.py --folder ~/Documents --skip-text-mode --depth 2
```

### Example Output

```
Scanning for wallet files in: C:\Users\You\Documents

WalletBitcoinCore  [definite] C:\Users\You\Documents\bitcoincore-wallet.dat
WalletBlockchain   [definite] C:\Users\You\Documents\blockchain-v4.0-wallet.aes.json
WalletElectrum2    [definite] C:\Users\You\Documents\electrum2-wallet
WalletMetamask     [definite] C:\Users\You\Documents\metamask_vault

Summary:
  Files scanned: 156
  Wallets found: 4
  Breakdown:
    WalletBitcoinCore: 1
    WalletBlockchain: 1
    WalletElectrum2: 1
    WalletMetamask: 1
```

### Supported Wallet Types

Wallet mode detects all wallet types supported by BTCRecover, including:
- Bitcoin Core / Litecoin Core / Dogecoin Core wallets (`.dat`)
- Blockchain.com wallets (v0, v2, v3, v4)
- Electrum wallets (1.x, 2.x, loose key variants)
- MetaMask vaults and persist-root files
- MultiBit Classic and MultiBit HD wallets
- Block.io request/change JSON files
- Dogechain.info wallet files
- btc.com parsed wallet data
- Ethereum keystore files
- Coinomi wallet private keys
- And many more

At the start of a wallet scan, `walletfinder.py` prints the full list of wallet file types it will check (e.g. `Wallet file types checked (22): WalletBitcoinCore, WalletBlockchain, …`). A few types need an optional Python module in order to load; if one is missing, a warning is shown so you know that type could be skipped, along with the command to install it — for example:

```
[WARNING] Module missing: BitGo wallets may not be detected/loaded (pip3 install sjcl).
[WARNING] Module missing: Toast wallets may not be detected/loaded (pip3 install PyNaCl).
```

Installing the full requirements (`pip3 install -r requirements-walletfinder.txt`) provides every module, so these warnings normally only appear if you used the lightweight subset.

## Mnemonic Mode (Text Mode)

Mnemonic mode scans text files for words from common seed wordlists and private keys (WIF, BIP38, BIP32 extended keys). It detects two patterns:
- **Sequential matches**: N or more wordlist words appearing consecutively in file text (e.g., `"abandon ability about absorb abstract absurd"`)
- **Scattered matches**: N unique wordlist words found anywhere in a file

### Basic Usage

Scan for mnemonic phrases only (skip wallet-file detection) with default thresholds (12 sequential, 12 scattered):
```
python walletfinder.py --folder /path/to/search --skip-wallet-mode
```

Customize detection thresholds:
```
python walletfinder.py --folder ~/Notes --skip-wallet-mode --min-sequential 4 --min-scattered 8
```

Limit depth and lower thresholds for quick checks:
```
python walletfinder.py --folder . --skip-wallet-mode --depth 1 --min-sequential 3 --min-scattered 6
```

### Numbered and Bulleted Seed Lists

Seeds are often written as a numbered or bulleted list, one word per line:

```
1. drift
2. speed
3. come
...
```

Sequential detection treats list markers — plain numbers (`1`, `12)`, `3.`) and pure-punctuation bullets (`-`, `*`) — as **non-breaking separators**, so the words above still count as one consecutive run of 12 and are validated by checksum. Only the wordlist words count toward the run length.

### Checksum Validation

When a sequential match reaches a valid seed length for its type, BTCRecover validates the checksum to confirm it's a real seed phrase rather than random words:

| Wordlist | Valid Lengths | Checksum Method |
|----------|---------------|-----------------|
| BIP39 English | 12, 15, 18, 21, 24 | SHA-256 of entropy bits |
| Electrum Legacy / Blockchain v2 | 1–13, 24 | HMAC-SHA512 first byte |
| Blockchain v3/v4/v5/v6 | Multiples of 3 (min 3) | Version + SHA-256 of payload |
| SLIP39 | Variable (4+ words) | Shamir share CRC validation |

By default, only **checksum-valid** sequential matches are displayed. Files whose only signal is a **scattered** match (unique wordlist words found spread through the file, with no checksum-valid sequential run) and no private keys are suppressed from the per-file output, because scattered words alone can't be validated and are a common source of false positives. Use `--debug` to see all sequential matches (including those that fail checksum) and scattered-only files.

### Example Output

```
Scanning for mnemonic words and private keys in: C:\Users\You\Documents
Wordlists loaded:
  BIP39 English: 2048 words
  Electrum Legacy / Blockchain v2: 1626 words
  Blockchain v3: 65591 words
  SLIP39: 1024 words

C:\Users\You\Documents\wallet_notes.txt (512 bytes)
  [Mnemonic: BIP39 English]
    Sequential match (12 words): abandon ability about absorb abstract absurd abuse access accident account accurate across (checksum valid)
    Scattered unique matches: 18

Summary:
  Files scanned: 42
  Matches found: 1
```

### Debug Mode

With `--debug`, all sequential matches are shown (including those that fail checksum), and files with only non-checksum-valid results are included in output. This is useful for finding partial seeds, notes with fragments, or identifying false positives:

```
python walletfinder.py --folder ~/Notes --skip-wallet-mode --debug
```

Example debug output showing a sequential match without valid checksum:
```
C:\Users\You\Documents\notes.txt (256 bytes)
  [Mnemonic: BIP39 English]
    Sequential match (15 words): abandon ability about absorb abstract absurd abuse access accident account accurate across act action
    Scattered unique matches: 24
```

### Wordlists Checked

- **BIP39 English** (2048 words) - Used by most hardware wallets and BIP39-compliant software wallets
- **SLIP39** (1024 words) - Used by Trezor T, Keepkey, Coldcard, and other SLIP39-compatible devices
- **Electrum Legacy / Blockchain v2** (1626 words) - Electrum 1.x and early Blockchain.info wallets
- **Blockchain v3** (65,590 words) - Modern Blockchain.com wallet recovery phrases

### Thresholds Explained

`--min-sequential N` controls how many consecutive wordlist words must appear in a row to trigger a match. A standard 12-word BIP39 seed will produce a sequential run of 12. The default is 12, which filters out most false positives from casual text. Lowering this threshold (e.g., `--min-sequential 4`) can help find partial seeds or notes where only fragments are recorded.

`--min-scattered N` controls how many unique wordlist words must appear anywhere in a file to trigger a match. This catches files that contain wallet data with embedded mnemonics, exported seed lists, or notes with multiple phrases scattered throughout.

## Exclusions and Limits

Both modes automatically exclude:
- Hidden directories (`.git`, `.venv`, etc.)
- Build artifacts (`node_modules`, `__pycache__`)
- Files larger than 16 KB (mnemonic mode) or wallet file size limit (wallet mode)
- Paths listed in `walletfinder-exclusionlist.txt` (see below)

Use `--depth N` to control how deep the scan recurses into subdirectories. A depth of `0` scans only the top-level folder; `1` includes one level of subdirectories, and so on. Omit `--depth` for unlimited recursion.

### Exclusion List (`walletfinder-exclusionlist.txt`)

`walletfinder.py` reads a bundled `walletfinder-exclusionlist.txt` and skips any file whose path matches one of its entries. The bundled list has two parts:

1. **Curated default exclusions** for common false positives that show up on full-system scans: Chromium/Edge/Brave browser data files that happen to parse as unencrypted wallet protobufs (e.g. `AdSelectionAttestationsPreloaded/`), Windows Settings content files, spell-check dictionaries, some third-party app telemetry/cache files, Linux system wordlists, crypto library source trees (`libwally`, python `bitcoinlib`, `uBitcoin` — their docs, examples, and tests are full of spec seeds and example keys, and get vendored inside other projects), and Python package directories / pip caches (`site-packages/`, `dist-packages/`, pip's HTTP cache). Delete a line if you *do* want those locations scanned.
2. **Auto-generated repo entries** below the `--- Entries below this marker are managed by ... ---` line: BTCRecover's own test wallets and example seed/key files (under `btcrecover/test/`, `docs/`, `lib/`, and others) that would otherwise be reported when you scan the repo itself with `python walletfinder.py --folder .`.

**Entry syntax** (matched case-insensitively against each scanned path **relative to the scan root**, with `/` separators):

- Lines without wildcards are **path substrings** — `site-packages/` skips any `site-packages` directory at any depth; repo-relative entries like `btcrecover/test/` only take effect when the repository itself is scanned.
- Lines containing `*` or `?` are **shell-style globs** (like `.gitignore` patterns): `*.settingcontent-ms` skips those files at any depth, and `CapCut/Apps/*/Resources/bench/score.dat` matches with any version directory in the middle. Note that `*` also matches across `/`.
- `#` starts a comment, either on its own line or after an entry.

You can add your own entries by hand anywhere above the marker line; they are preserved when the list is regenerated. If you add, remove, or rename repo files containing example seeds/keys, regenerate the auto-generated section with:

```
python walletfinder.py --update-exclusions
```

This rescans the repository and merges any newly-matching files into the section below the marker (everything above the marker — the curated defaults and your own entries — is preserved verbatim).

> **Note on suppressed matches:** in Mnemonic Mode the summary reports `Matches found` (files actually shown) and, separately, `Suppressed matches (viewable if running with --debug)` — files whose only signal was a weak *scattered* match with no checksum-valid seed or private key, or whose only checksum-valid seed was a **well-known spec test mnemonic**. Famous test seeds (like the BIP39 spec vectors `abandon abandon … about` and `legal winner thank year wave …`) appear constantly in crypto libraries, documentation, and cached packages, so they are hidden by default; rerun with `--debug` to see them tagged as `(checksum valid, well-known test seed)`.

## Tips

- **Scan your entire home directory** with a limited depth to find wallets you forgot about:
  ```
  python walletfinder.py --folder ~ --depth 3
  ```
- **Check backup folders** for mnemonic seeds before deleting them (text/documents only):
  ```
  python walletfinder.py --folder ~/Desktop/backup --skip-wallet-mode
  ```
- **Quick check of a single folder** without deep recursion:
  ```
  python walletfinder.py --folder ./wallets --depth 0
  ```
- **Find partial seeds and fragments** by lowering the sequential threshold with debug output:
  ```
  python walletfinder.py --folder ~/Notes --skip-wallet-mode --min-sequential 4 --debug
  ```
- **Scan for private keys** (WIF, BIP38, extended keys) alongside mnemonics:
  ```
  python walletfinder.py --folder ~/Documents --skip-wallet-mode
  ```

## Private Key Detection

Text mode also scans for Bitcoin private keys in various formats:
- **WIF** (Wallet Import Format): Compressed (`K...`, `L...`), uncompressed (`5...`), and testnet (`c...`)
- **BIP38**: Encrypted paper wallet keys (`6P...`)
- **BIP32 Extended Keys**: Both private (`xprv`, `yprv`, `zprv`, etc.) and public (`xpub`, `ypub`, `zpub`, etc.)

Private key detection uses regex pattern matching with length validation. All detected keys pass Base58Check format requirements by construction of the patterns.

Extended **public** keys are reported under a `[Public Key: …]` heading (an xpub cannot spend funds, but it reveals a wallet's addresses and is a strong hint that a related private key or seed exists nearby); everything else — WIF, BIP38, and extended private keys — appears under `[Private Key: …]`.
