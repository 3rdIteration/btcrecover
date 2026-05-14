---
name: locate-wallet-file
description: Help a user find an encrypted cryptocurrency wallet file on their system when they are not sure where it is. Recognises wallets by their internal content fingerprints (Bitcoin Core BDB, Electrum JSON / BIE1, MultiBit HD, bitcoinj, Blockchain.com, Bither SQLite, Coinomi, MetaMask vault, Ethereum UTC keystore, mSIGNA, BIP38) rather than by filename. Invoke from the main BTCRecover recovery skill (Step 5d) or any time a user says they have "lost" their wallet file. Returns a list of candidate paths to the user; never paste wallet contents back into the chat.
---

# Locate Wallet File Skill

This skill helps an AI agent find a cryptocurrency wallet file on a user's
machine when the user doesn't know (or doesn't remember) where it is, or when
the file has been renamed / stripped of its extension. It is a sub-skill of
the main BTCRecover recovery skill ([`SKILL.md`](../../SKILL.md), Step 5d) and
can also be used standalone.

> **Safety.** Recognising wallet files by their internal contents does **not**
> require the contents to leave the user's machine. It is therefore safe to
> walk the user through this search even on a cloud-hosted agent, *provided*
> that the matches themselves (paths, filenames, and especially file
> contents) stay on the user's machine and are never pasted back into the
> chat or uploaded anywhere. Only ask the user to share the *path* of a
> match once they have confirmed it themselves.

---

## When to invoke

* The user has a recovery target (wants to recover a password / passphrase /
  BIP38 key) but doesn't know where the wallet file is on disk.
* The user has a backup drive, phone backup, or cloud-sync folder and wants
  to know whether it contains a wallet.
* The user has a file they suspect is a wallet but it has a non-obvious
  filename (no extension, renamed, copied off a phone, etc.).

## What you need from the user

1. **One or more paths to search** — home directory, an external drive, a
   backup folder, etc. Ask explicitly; do not scan the whole filesystem by
   default.
2. **Which wallet software they think they used**, if they have any guess.
   This narrows the search; if they don't know, scan for all fingerprints.
3. **Permission** to read files in those paths. On macOS this may require
   Full Disk Access for the terminal app.

## How to identify wallets

**Recognise wallets by their internal contents, not by their filename.** Real
filenames vary a lot — users rename files, mobile backups strip extensions,
and many wallets share generic names like `wallet.dat` or `default_wallet`.

The BTCRecover repository ships sample wallets in
[`btcrecover/test/test-wallets/`](../../btcrecover/test/test-wallets/). Open
the samples first and learn what each format looks like *inside*, then use
those fingerprints when scanning the user's system. Confirm a fingerprint
against the sample before relying on it.

### Content fingerprints

| Wallet | Typical filenames | Internal fingerprint |
| --- | --- | --- |
| **Bitcoin / Litecoin / Dogecoin Core** | `bitcoincore-*-wallet.dat`, `litecoincore-*-wallet.dat`, `dogecoincore-*-wallet.dat`, often just `wallet.dat` | Berkeley DB binary file; first bytes contain the BDB magic; body has strings like `\x04name`, `\x04mkey`, `\x04ckey`, `\x04default`. |
| **Electrum (1.x – 4.x unencrypted)** | `electrum*-wallet`, `electrum4_4_3_unencrypted`, `default_wallet` | JSON object whose top-level keys include `seed_version`, `wallet_type`, `keystore`, etc. |
| **Electrum 2.8+ fully encrypted** | same as above | Base64 blob starting with `BIE1`. |
| **MultiBit HD** | `mbhd.wallet.aes` | Binary AES-CBC blob; usually sits next to a `mbhd.yaml` in an MBHD application directory. |
| **bitcoinj / MultiBit Classic** | `multibit.wallet.bitcoinj.*`, `bitcoinj-wallet.wallet` | Protobuf binary starting with `\x0a\x16org.bitcoin.production` (or similar `org.<network>.production`). |
| **Blockchain.com** | `blockchain-v*-wallet.aes.json`, real-world name **`wallet.aes.json`** | JSON with top-level keys such as `version`, `pbkdf2_iterations`, and `payload` (payload is a base64 string). |
| **Bither** | `bither-wallet.db`, `bither-hdonly-wallet.db` | SQLite 3 database (`SQLite format 3\x00` header) containing tables like `passwords_seed`, `hd_seeds`, `addresses`. |
| **Coinomi** | `coinomi.wallet.android`, `coinomi.wallet.desktop` | bitcoinj protobuf wrapped with Coinomi's encryption metadata; often paired with a `wallet-header` file on Android. |
| **MetaMask** | `metamask.*persist-root`, `metamask*vault*` | JSON vault containing a `data`, `iv`, and `salt` field (the `data` is a base64 blob). |
| **Ethereum keystore (UTC)** | `utc-keystore-v3-*.json` | JSON with `version: 3`, a `crypto` object containing `ciphertext`, `cipherparams`, `kdf` (`scrypt` or `pbkdf2`), and `mac`. |
| **mSIGNA / CoinVault** | `msigna-wallet.vault` | SQLite 3 database with tables specific to mSIGNA (e.g. `Keychain`, `Account`). |
| **BIP38 encrypted private key** | usually a `.txt` or a paper note | ASCII string starting with `6P`. |

## Search workflow

1. Ask the user which path(s) they want scanned, and confirm whether the
   agent should run the scan on their behalf or hand them commands to run
   themselves.
2. **Combine name-based hints with content fingerprints.** Examples:
   * Find all JSON files and grep for `"payload"` *and* `"pbkdf2_iterations"`
     to spot Blockchain.com wallets regardless of filename.
   * Look for the BDB magic to spot Bitcoin/Litecoin/Dogecoin Core wallets
     that have been renamed.
   * Look for files starting with `SQLite format 3\x00` and then test which
     tables they contain to distinguish Bither from mSIGNA from unrelated
     SQLite databases.
   * Look for files starting with `BIE1` (Electrum 2.8+ encrypted) or `6P`
     (BIP38).
3. Present candidate matches to the user with their paths and the
   fingerprint that matched. **Do not paste file contents into chat.**
4. Let the user confirm which candidate is the wallet they want to recover.

## When you're done

Return the path of the confirmed wallet file to the caller (or to the user).
If invoked from the main BTCRecover skill, control then continues at Step 5c
("Wallet-file recoveries → put the file in the working folder").

If nothing matched, tell the user honestly: explain which paths were
searched, which fingerprints were checked, and suggest other likely
locations (cloud-sync folders, phone backups, old external drives, an
exported keystore on a hardware-wallet companion app, etc.).
