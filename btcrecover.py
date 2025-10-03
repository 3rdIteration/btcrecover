#!/usr/bin/env python

# btcrecover.py -- Bitcoin wallet password recovery tool
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

from btcrecover import btcrpass, success_alert
import sys, multiprocessing

if __name__ == "__main__":
	print()
	print("Starting", btcrpass.full_version(),
		  file=sys.stderr if any(a.startswith("--listp") for a in sys.argv[1:]) else sys.stdout)  # --listpass

	btcrpass.parse_arguments(sys.argv[1:])
	(password_found, not_found_msg) = btcrpass.main()

        if isinstance(password_found, str):
                success_alert.start_success_beep()
                print()
                print("If this tool helped you to recover funds, please consider donating 1% of what you recovered, in your crypto of choice to:")
                print("BTC: 37N7B7sdHahCXTcMJgEnHz7YmiR4bEqCrS ")
		print("BCH: qpvjee5vwwsv78xc28kwgd3m9mnn5adargxd94kmrt ")
		print("LTC: M966MQte7agAzdCZe5ssHo7g9VriwXgyqM ")
		print("ETH: 0x72343f2806428dbbc2C11a83A1844912184b4243 ")

		#print("VTC: vtc1qxauv20r2ux2vttrjmm9eylshl508q04uju936n ")
		#print("ZEN: znUihTHfwm5UJS1ywo911mdNEzd9WY9vBP7 ")
		#print("DASH: Xx2umk6tx25uCWp6XeaD5f7CyARkbemsZG ")
		#print("DOGE: DMQ6uuLAtNoe5y6DCpxk2Hy83nYSPDwb5T ")
		#print("XMR: 48wnuLYsPY7ewLQyF4RLAj3N8CHH4oBBcaoDjUQFiR4VfkgPNYBh1kSfLx94VoZSsGJnuUiibJuo7FySmqroAi6c1MLWHYF ")
		#print("MONA: mona1q504vpcuyrrgr87l4cjnal74a4qazes2g9qy8mv ")
		#print("XVG: DLZDT48wfuaHR47W4kU5PfW1JfJY25c9VJ")
		print()
		print("Find me on Reddit @ https://www.reddit.com/user/Crypto-Guide")
		print()
		print("You may also consider donating to Gurnec, who created and maintained this tool until late 2017 @ 3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4")
		print()
                btcrpass.safe_print("Password found: '" + password_found + "'")
                if any(ord(c) < 32 or ord(c) > 126 for c in password_found):
                        print("HTML Encoded Password:   '" + password_found.encode("ascii", "xmlcharrefreplace").decode() + "'")
                success_alert.wait_for_user_to_stop()
                retval = 0

        elif not_found_msg:
                print(not_found_msg, file=sys.stderr if btcrpass.args.listpass else sys.stdout)
                success_alert.beep_failure_once()
                retval = 0

        else:
                success_alert.beep_failure_once()
                retval = 1  # An error occurred or Ctrl-C was pressed

	# Wait for any remaining child processes to exit cleanly (to avoid error messages from gc)
        for process in multiprocessing.active_children():
                process.join(1.0)

        success_alert.stop_success_beep()

        sys.exit(retval)
