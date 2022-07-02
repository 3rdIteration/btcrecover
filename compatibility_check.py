import sys
if sys.version_info < (3, 6):
	sys.stdout.write("\n\n************************************ Python Version Error ******************************************\n\n")
	sys.stdout.write("Sorry, BTCRecover no longer supports Python2 as it is officially End-of-Life...\n\n")
	sys.stdout.write("Some features of this tool also require Python 3.7 or above to work....\n\n")
	sys.stdout.write("You will need either to upgrade to at least Python 3.7 or download the final Python2 release.\n\n")
	sys.stdout.write("Note: Python2 versions of this tool are now unsupported and will not receive improvements or fixes\n\n")
	sys.stdout.write("Python2 releases and documentation for installing and using this tool with Python3 can be found at from https://github.com/3rdIteration/btcrecover.\n\n")
	sys.stdout.write("************************************ Python Version Error ******************************************\n\n")
	sys.exit(1)

