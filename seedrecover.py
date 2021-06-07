#!/usr/bin/env python3

# seedrecover.py -- Bitcoin mnemonic sentence recovery tool
# Copyright (C) 2014-2017 Christopher Gurnee
#
# This program is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4
#
#                      Thank You!

# PYTHON_ARGCOMPLETE_OK - enables optional bash tab completion

import compatibility_check

from btcrecover import btcrseed
import sys, multiprocessing

if __name__ == "__main__":
    print()
    print("Starting", btcrseed.full_version())

    btcrseed.register_autodetecting_wallets()
    mnemonic_sentence, path_coin = btcrseed.main(sys.argv[1:])

    if mnemonic_sentence:
        if not btcrseed.tk_root:  # if the GUI is not being used
            print()
            print(
                "If this tool helped you to recover funds, please consider donating 1% of what you recovered, in your crypto of choice to:")
            print("BTC: 37N7B7sdHahCXTcMJgEnHz7YmiR4bEqCrS ")
            print("BCH: qpvjee5vwwsv78xc28kwgd3m9mnn5adargxd94kmrt ")
            print("LTC: M966MQte7agAzdCZe5ssHo7g9VriwXgyqM ")
            print("ETH: 0x72343f2806428dbbc2C11a83A1844912184b4243 ")

            # Selective Donation Addressess depending on path being recovered... (To avoid spamming the dialogue with shitcoins...)
            # TODO: Implement this better with a dictionary mapping in seperate PY file with BTCRecover specific donation addys... (Seperate from YY Channel)
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

        # print this if there's any chance of Unicode-related display issues
        if any(ord(c) > 126 for c in mnemonic_sentence):
            print("HTML Encoded Seed:", mnemonic_sentence.encode("ascii", "xmlcharrefreplace").decode())

        if btcrseed.tk_root:      # if the GUI is being used
            btcrseed.show_mnemonic_gui(mnemonic_sentence, path_coin)

        retval = 0

    elif mnemonic_sentence is None:
        retval = 1  # An error occurred or Ctrl-C was pressed inside btcrseed.main()

    else:
        retval = 0  # "Seed not found" has already been printed to the console in btcrseed.main()

    # Wait for any remaining child processes to exit cleanly (to avoid error messages from gc)
    for process in multiprocessing.active_children():
        process.join(1.0)

    sys.exit(retval)
