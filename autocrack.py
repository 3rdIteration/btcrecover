import os
import sys
import argparse
import subprocess


if __name__ == "__main__":
    password = ''
    argparser = argparse.ArgumentParser(
        description='Set wallet on auto craking')
    argparser.add_argument('--wallet', type=str,
                           help='wallet file to crack', required=True)
    argparser.add_argument('--passlist', type=str,
                           help='path to wordlists', required=True)
    argparser.add_argument('--global_ws', type=str,
                           help='global words', required=True)
    args = argparser.parse_args()
    input_path = args.passlist
    wallet = args.wallet
    global_ws = args.global_ws
    if not os.path.isfile(wallet):
        print('The path specified does not exist')
        sys.exit()
    included_extensions = ['txt']
    file_names = [fn for fn in os.listdir(input_path)
                  if any(fn.endswith(ext) for ext in included_extensions)]
    for wordlist in file_names:
        wordlist = os.path.join(input_path, wordlist)
        starting = f'telegram-send --pre "Starting {wallet} with wordlist {wordlist}"'
        finished = f'telegram-send --pre "Finished {wallet} with wordlist {wordlist}"'
        command = f'python3 btcrecover.py --wallet {wallet} --passwordlist {wordlist} --enable-opencl --dsw --enable-gpu'
        if(global_ws is not None):
            command += f' --global_ws {global_ws}'
        subprocess.run(starting, shell=True)
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE)
        result = str(result.stdout.decode())
        if "Password found:" in result:
            sys.exit()
        subprocess.run(finished, shell=True)
print('All wordlist are checked')
sys.exit()
