"""Console entry points for the password and seed recovery tools.

The logic here used to live in the top-level ``btcrecover.py`` and
``seedrecover.py`` launcher scripts. It was moved into the package so that:

* the behaviour is importable and testable rather than trapped in a
  ``if __name__ == "__main__"`` block, and
* ``pyproject.toml`` can expose real ``console_scripts`` entry points.

The top-level launcher scripts now simply run the Python-version gate in
``compatibility_check`` and delegate to the functions below, so behaviour for
``python btcrecover.py ...`` is unchanged.
"""

import json
import multiprocessing
import sys

from btcrecover import btcrpass, btcrseed, success_alert

__all__ = [
    "password_recovery_main",
    "seed_recovery_main",
    "password_console_entry",
    "seed_console_entry",
]

# Exit code for each api result status, matching the human-readable CLI paths:
# a found or exhausted search is a clean exit; an interrupt or error is not.
_STATUS_EXIT_CODE = {
    "found": 0,
    "not_found": 0,
    "interrupted": 1,
    "error": 1,
}


def _emit_json_result(result):
    """Print *result* as one JSON object on stdout and return the exit code."""
    print(json.dumps(result.to_dict()))
    return _STATUS_EXIT_CODE.get(result.status, 1)

_DONATION_LINES = (
    "If this tool helped you to recover funds, please consider donating 1% of what you recovered, in your crypto of choice to:",
    "BTC: 37N7B7sdHahCXTcMJgEnHz7YmiR4bEqCrS ",
    "BCH: qpvjee5vwwsv78xc28kwgd3m9mnn5adargxd94kmrt ",
    "LTC: M966MQte7agAzdCZe5ssHo7g9VriwXgyqM ",
    "ETH: 0x72343f2806428dbbc2C11a83A1844912184b4243 ",
)


def _join_active_children():
    # Wait for any remaining child processes to exit cleanly (to avoid error
    # messages from gc).
    for process in multiprocessing.active_children():
        process.join(1.0)


def password_recovery_main(argv=None):
    """Run the password recovery tool. Returns the process exit code."""
    if argv is None:
        argv = sys.argv[1:]

    if "--json" in argv:
        from btcrecover import api

        result = api.recover_password(argv, quiet=True)
        return _emit_json_result(result)

    print()
    print(
        "Starting",
        btcrpass.full_version(),
        file=sys.stderr if any(a.startswith("--listp") for a in argv) else sys.stdout,
    )  # --listpass

    btcrpass.parse_arguments(argv)
    (password_found, not_found_msg) = btcrpass.main()

    if isinstance(password_found, str):
        success_alert.start_success_beep()
        print()
        for line in _DONATION_LINES:
            print(line)
        print()
        print("Find me on Reddit @ https://www.reddit.com/user/Crypto-Guide")
        print()
        print(
            "You may also consider donating to Gurnec, who created and maintained this tool until late 2017 @ 3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4"
        )
        print()
        btcrpass.safe_print("Password found: '" + password_found + "'")
        if any(ord(c) < 32 or ord(c) > 126 for c in password_found):
            print(
                "HTML Encoded Password:   '"
                + password_found.encode("ascii", "xmlcharrefreplace").decode()
                + "'"
            )
        success_alert.wait_for_user_to_stop()
        retval = 0

    elif not_found_msg:
        print(not_found_msg, file=sys.stderr if btcrpass.args.listpass else sys.stdout)
        success_alert.beep_failure_once()
        retval = 0

    else:
        success_alert.beep_failure_once()
        retval = 1  # An error occurred or Ctrl-C was pressed

    _join_active_children()
    success_alert.stop_success_beep()
    return retval


def seed_recovery_main(argv=None):
    """Run the seed/mnemonic recovery tool. Returns the process exit code."""
    if argv is None:
        argv = sys.argv[1:]

    if "--json" in argv:
        from btcrecover import api

        result = api.recover_seed(argv, quiet=True)
        return _emit_json_result(result)

    print()
    print("Starting", btcrseed.full_version())

    btcrseed.register_autodetecting_wallets()
    mnemonic_sentence, path_coin = btcrseed.main(argv)

    if mnemonic_sentence:
        success_alert.start_success_beep()
        if not btcrseed.tk_root:  # if the GUI is not being used
            print()
            print(
                "If this tool helped you to recover funds, please consider donating 1% of what you recovered, in your crypto of choice to:")
            print("BTC: 37N7B7sdHahCXTcMJgEnHz7YmiR4bEqCrS ")
            print("BCH: qpvjee5vwwsv78xc28kwgd3m9mnn5adargxd94kmrt ")
            print("LTC: M966MQte7agAzdCZe5ssHo7g9VriwXgyqM ")
            print("ETH: 0x72343f2806428dbbc2C11a83A1844912184b4243 ")

            # Selective donation addresses depending on the path being recovered
            # (to avoid spamming the dialogue with every coin).
            if path_coin == 28:
                print("VTC: vtc1qxauv20r2ux2vttrjmm9eylshl508q04uju936n ")

            if path_coin == 22:
                print("MONA: mona1q504vpcuyrrgr87l4cjnal74a4qazes2g9qy8mv ")

            if path_coin == 5:
                print("DASH: Xx2umk6tx25uCWp6XeaD5f7CyARkbemsZG ")

            if path_coin == 121:
                print("ZEN: znUihTHfwm5UJS1ywo911mdNEzd9WY9vBP7 ")

            if path_coin == 3:
                print("DOGE: DMQ6uuLAtNoe5y6DCpxk2Hy83nYSPDwb5T ")

            print()
            print("Find me on Reddit @ https://www.reddit.com/user/Crypto-Guide")
            print()
            print(
                "You may also consider donating to Gurnec, who created and maintained this tool until late 2017 @ 3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4")
            print()
            print("Seed found:", mnemonic_sentence)  # never dies from printing Unicode
            if isinstance(btcrseed.loaded_wallet, btcrseed.WalletSLIP39Seed):
                print(
                    "NOTE: SLIP39 seed recovery matches checksums, so needs to be manually verified"
                )

        # print this if there's any chance of Unicode-related display issues
        if any(ord(c) > 126 for c in mnemonic_sentence):
            print("HTML Encoded Seed:", mnemonic_sentence.encode("ascii", "xmlcharrefreplace").decode())

        if not btcrseed.tk_root:
            success_alert.wait_for_user_to_stop()

        if btcrseed.tk_root:      # if the GUI is being used
            btcrseed.show_mnemonic_gui(mnemonic_sentence, path_coin)

        retval = 0

    else:
        success_alert.beep_failure_once()
        if mnemonic_sentence is None:
            retval = 1  # An error occurred or Ctrl-C was pressed inside btcrseed.main()
        else:
            retval = 0  # "Seed not found" has already been printed by btcrseed.main()

    _join_active_children()
    success_alert.stop_success_beep()
    return retval


def password_console_entry():
    """``console_scripts`` entry point for the ``btcrecover`` command."""
    sys.exit(password_recovery_main())


def seed_console_entry():
    """``console_scripts`` entry point for the ``seedrecover`` command."""
    sys.exit(seed_recovery_main())
