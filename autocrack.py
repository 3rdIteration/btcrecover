import os
import sys
import argparse
import subprocess
from itertools import islice

helpmessage = '''
A simple utility for automation of wallet cracking

SYNTAX:
    python3 autocrack.py --wallet wallets/wallet.dat --passlist wordlist/folder 

--wallet : wallet file to crack (wallet.dat)[REQUIRED]
--passlist : folder having list of wordlist[REQUIRED]
--start : starting postion (optional)
--showlist : print all wordlist 
'''

if __name__ == "__main__":
    if(len(sys.argv) < 2):
        print(helpmessage)
        sys.exit()
    argparser = argparse.ArgumentParser(
        description='Set wallet on auto craking')
    argparser.add_argument('--wallet', type=str,
                           help='wallet file to crack')
    argparser.add_argument('--passlist', type=str,
                           help='path to wordlists')
    argparser.add_argument('--global_ws', type=str,
                           help='global words (default : 4096)')
    argparser.add_argument('--start', type=str,
                           help='start with nth wordlist\nn ->Start with nth wordlist')
    argparser.add_argument('--showlist', default=False,
                           help='display all the wordlist', action='store_true')
    args = argparser.parse_args()
    input_path = args.passlist
    wallet = args.wallet
    global_ws = args.global_ws
    showlist = args.showlist
    startpos = args.start
    if(input_path != 'None'):
        if not os.path.exit(input_path):
            print('The specified wallet.dat does not exist')
            sys.exit()
        included_extensions = ['txt']
        file_names = [fn for fn in os.listdir(input_path)
                      if any(fn.endswith(ext) for ext in included_extensions)]
        total_files = len(file_names)
        file_names.sort()
        if(showlist):
            for wordlist in file_names:
                print(wordlist)
            sys.exit()
        if(startpos is not None):
            startpos -= 1
        else:
            startpos = 0
        if(wallet != 'None'):
            if not os.path.isfile(wallet):
                print('The specified wallet.dat does not exist')
                sys.exit()
            else:
                for wordlist in islice(file_names, startpos, None):
                    wordlist = os.path.join(input_path, wordlist)
                    starting = f'telegram-send --pre "Starting {wallet} with wordlist {wordlist}"'
                    finished = f'telegram-send --pre "Finished {wallet} with wordlist {wordlist}\nRemaining wordlist {total_files}"'
                    command = f'python3 btcrecover.py --wallet {wallet} --passwordlist {wordlist} --enable-opencl --dsw --enable-gpu'
                    if(global_ws is not None):
                        command += f' --global_ws {global_ws}'
                    subprocess.run(starting, shell=True)
                    result = subprocess.run(
                        command, shell=True, stdout=subprocess.PIPE)
                    result = str(result.stdout.decode())
                    if "Password found:" in result:
                        sys.exit()
                    subprocess.run(finished, shell=True)
                    total_files -= 1
        else:
            print('Syntax Error : --wallet is missing')
            sys.exit()
    else:
        print('Syntax Error: --passlist is missing')
        sys.exit()
    subprocess.run(
        'telegram-send --pre "All Wordlist are checked\nJob Done"', shell=True)
    sys.exit()
