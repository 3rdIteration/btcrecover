# WalletFinder - Scanning for Wallet Files and Mnemonic Phrases

`walletfinder.py` is a utility script included with BTCRecover that helps you locate wallet files and mnemonic seed phrases hidden in directories on your computer. It has two operating modes: **Wallet Mode** (auto-detects supported wallet file formats) and **Mnemonic Mode** (scans text files for BIP39, SLIP39, Electrum Legacy, or Blockchain wordlist words).

## Installation

`walletfinder.py` is included in the BTCRecover repository root. No additional installation is required beyond having BTCRecover set up. If you have BTCRecover installed via pip, the script will be available on your PATH as `walletfinder`.

## Wallet Mode (Default)

Wallet mode uses BTCRecover's built-in wallet auto-detection to scan a directory recursively for supported wallet files. It reports each detected file with its type and confidence level.

### Basic Usage

Scan a single folder:
```
python walletfinder.py --folder /path/to/search
```

Limit recursion depth (e.g., only 2 levels deep):
```
python walletfinder.py --folder ~/Documents --depth 2
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

## Mnemonic Mode (Text Mode)

Mnemonic mode scans text files for words from common seed wordlists and private keys (WIF, BIP38, BIP32 extended keys). It detects two patterns:
- **Sequential matches**: N or more wordlist words appearing consecutively in file text (e.g., `"abandon ability about absorb abstract absurd"`)
- **Scattered matches**: N unique wordlist words found anywhere in a file

### Basic Usage

Scan for mnemonic phrases with default thresholds (12 sequential, 12 scattered):
```
python walletfinder.py --folder /path/to/search --text-mode
```

Customize detection thresholds:
```
python walletfinder.py --folder ~/Notes --text-mode --min-sequential 4 --min-scattered 8
```

Limit depth and lower thresholds for quick checks:
```
python walletfinder.py --folder . --text-mode --depth 1 --min-sequential 3 --min-scattered 6
```

### Checksum Validation

When a sequential match reaches a valid seed length for its type, BTCRecover validates the checksum to confirm it's a real seed phrase rather than random words:

| Wordlist | Valid Lengths | Checksum Method |
|----------|---------------|-----------------|
| BIP39 English | 12, 15, 18, 21, 24 | SHA-256 of entropy bits |
| Electrum Legacy / Blockchain v2 | 1–13, 24 | HMAC-SHA512 first byte |
| Blockchain v3/v4/v5/v6 | Multiples of 3 (min 3) | Version + SHA-256 of payload |
| SLIP39 | Variable (4+ words) | Shamir share CRC validation |

By default, only **checksum-valid** sequential matches are displayed. Files with no checksum-valid results and no private keys are suppressed from output. Use `--debug` to see all sequential matches including those that fail checksum validation.

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
python walletfinder.py --folder ~/Notes --text-mode --debug
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

Use `--depth N` to control how deep the scan recurses into subdirectories. A depth of `0` scans only the top-level folder; `1` includes one level of subdirectories, and so on. Omit `--depth` for unlimited recursion.

## Tips

- **Scan your entire home directory** with a limited depth to find wallets you forgot about:
  ```
  python walletfinder.py --folder ~ --depth 3
  ```
- **Check backup folders** for mnemonic seeds before deleting them:
  ```
  python walletfinder.py --folder ~/Desktop/backup --text-mode
  ```
- **Quick check of a single folder** without deep recursion:
  ```
  python walletfinder.py --folder ./wallets --depth 0
  ```
- **Find partial seeds and fragments** by lowering the sequential threshold with debug output:
  ```
  python walletfinder.py --folder ~/Notes --text-mode --min-sequential 4 --debug
  ```
- **Scan for private keys** (WIF, BIP38, extended keys) alongside mnemonics:
  ```
  python walletfinder.py --folder ~/Documents --text-mode
  ```

## Private Key Detection

Text mode also scans for Bitcoin private keys in various formats:
- **WIF** (Wallet Import Format): Compressed (`K...`, `L...`), uncompressed (`5...`), and testnet (`c...`)
- **BIP38**: Encrypted paper wallet keys (`6P...`)
- **BIP32 Extended Keys**: Both private (`xprv`, `yprv`, `zprv`, etc.) and public (`xpub`, `ypub`, `zpub`, etc.)

Private key detection uses regex pattern matching with length validation. All detected keys pass Base58Check format requirements by construction of the patterns.
