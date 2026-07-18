#!/usr/bin/env python

# download-blockchain-wallet.py -- Blockchain.com wallet file downloader
# Copyright (C) 2016, 2017 Christopher Gurnee
# Copyright (C) 2021-2026 Stephen Rothery
#
# This file is part of btcrecover.
#
# btcrecover is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# btcrecover is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

import sys, os.path, atexit, uuid, json, time

try:
    import requests
except ImportError:
    sys.exit("The 'requests' library is required. Install it with: pip3 install requests")

# The api_code (as of Feb 2 2017)
API_CODE = "1770d5d9-bcea-4d28-ad21-6cbd5be018a8"

prog = os.path.basename(sys.argv[0])

if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
    print("usage: {} [NEW_BLOCKCHAIN_WALLET_FILE]".format(prog))
    print()
    print("Downloads a Blockchain.com wallet file (wallet.aes.json).")
    print("You will be prompted to enter your wallet ID and approve")
    print("the login via email. If 2FA is enabled, you will also be")
    print("prompted for the 2FA code.")
    sys.exit(0)

if len(sys.argv) < 2:
    atexit.register(lambda: input("\nPress Enter to exit ..."))
    filename = "wallet.aes.json"
elif len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
    filename = sys.argv[1]
else:
    print("usage:", prog, "[NEW_BLOCKCHAIN_WALLET_FILE]", file=sys.stderr)
    sys.exit(2)

# Refuse to overwrite an existing file
if os.path.exists(filename):
    print("Error: {} already exists, won't overwrite".format(filename), file=sys.stderr)
    sys.exit(1)

print("Please enter your wallet's ID (e.g. 9bb4c672-563e-4806-9012-a3e8f86a0eca)")
wallet_id = str(uuid.UUID(input("> ").strip()))

# Base URLs to attempt (login.blockchain.com first, blockchain.info as fallback)
BASE_URLS = [
    "https://login.blockchain.com/",
    "https://blockchain.info/",
]

# Browser-like headers to avoid Cloudflare blocks
# Note: Update the Chrome version periodically to match current browser releases
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": "https://login.blockchain.com",
    "Referer": "https://login.blockchain.com/",
}


def try_download_wallet(base_url, session, wallet_id):
    """Attempt to download the wallet from the given base URL.

    Returns the wallet payload data on success, or raises on failure.
    """

    auth_token = None

    # Get an auth_token
    resp = session.post(base_url + "sessions", data="api_code=" + API_CODE)
    resp.raise_for_status()
    auth_token = resp.json()["token"]
    session.headers["Authorization"] = "Bearer " + auth_token

    # Try to download the wallet
    try:
        resp = session.get(
            base_url + "wallet/{}?format=json&api_code={}".format(wallet_id, API_CODE)
        )
        resp.raise_for_status()
        wallet_data = resp.json().get("payload")
    except requests.HTTPError as e:
        error_msg = ""
        try:
            error_msg = e.response.json().get("initial_error", e.response.text)
        except Exception:
            error_msg = e.response.text if e.response is not None else str(e)

        print(error_msg)

        if "unknown wallet identifier" in str(error_msg).lower():
            sys.exit(1)

        # Wait for the user to complete the requested authorization (email)
        time.sleep(5)
        print("Waiting for authorization (press Ctrl-C to give up)...")
        while True:
            poll_resp = session.get(
                base_url + "wallet/poll-for-session-guid?format=json&api_code=" + API_CODE
            )
            poll_data = poll_resp.json()
            if "guid" in poll_data:
                break
            time.sleep(5)
        print()

        # Try again to download the wallet (this shouldn't fail)
        resp = session.get(
            base_url + "wallet/{}?format=json&api_code={}".format(wallet_id, API_CODE)
        )
        resp.raise_for_status()
        wallet_data = resp.json().get("payload")

    # If there was no payload data, then 2FA is enabled
    while not wallet_data:
        print("This wallet has two-factor authentication enabled, please enter your 2FA code")
        two_factor = input("> ").strip()

        try:
            resp = session.post(
                base_url + "wallet",
                data="method=get-wallet&guid={}&payload={}&length={}&api_code={}".format(
                    wallet_id, two_factor, len(two_factor), API_CODE
                ),
            )
            resp.raise_for_status()
            wallet_data = resp.text
        except requests.HTTPError as e:
            error_text = ""
            try:
                error_text = e.response.text
            except Exception:
                error_text = str(e)
            print(error_text + "\n", file=sys.stderr)

    return wallet_data if isinstance(wallet_data, bytes) else wallet_data.encode("utf-8")


# Try each base URL
session = requests.Session()
session.headers.update(HEADERS)

wallet_data = None

for i, base_url in enumerate(BASE_URLS):
    try:
        wallet_data = try_download_wallet(base_url, session, wallet_id)
        break
    except (requests.RequestException, KeyError, ValueError) as e:
        if i < len(BASE_URLS) - 1:
            print("Download from {} failed ({}), trying next...".format(
                base_url.rstrip("/"), e
            ))
            # Reset session for next attempt
            session = requests.Session()
            session.headers.update(HEADERS)
        else:
            print("Error: Failed to download wallet from all endpoints.", file=sys.stderr)
            print("Last error: {}".format(e), file=sys.stderr)
            print("\nYou can still download your wallet manually using the browser method.", file=sys.stderr)
            print("See: https://btcrecover.readthedocs.io/en/latest/TUTORIAL/#downloading-blockchaincom-wallet-files", file=sys.stderr)
            sys.exit(1)

# Save the wallet
with open(filename, "wb") as wallet_file:
    wallet_file.write(wallet_data)

print("Wallet file saved as " + filename)
