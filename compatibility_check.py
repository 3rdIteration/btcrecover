import sys

# Officially supported versions are Python 3.10-3.14 (see docs/INSTALL.md); these
# are the versions BTCRecover is automatically tested against. Anything below 3.9
# is missing language/library features the tool relies on, so it is refused
# outright. Versions 3.9 will run but are untested -- use run-all-tests.py to
# check what works.
if sys.version_info < (3, 9):
	sys.stdout.write("\n\n************************************ Python Version Error ******************************************\n\n")
	sys.stdout.write("Sorry, this version of Python is too old to run BTCRecover.\n\n")
	sys.stdout.write("Officially supported versions are Python 3.10 - 3.14 (3.13 recommended).\n\n")
	sys.stdout.write("Please upgrade to a supported Python 3 release. Installation instructions:\n")
	sys.stdout.write("https://github.com/3rdIteration/btcrecover\n\n")
	sys.stdout.write("************************************ Python Version Error ******************************************\n\n")
	sys.exit(1)

