import os
import sys
import argparse
import subprocess


if __name__ == "__main__":
    password = ''
    argparser = argparse.ArgumentParser(
        description='Set wallet on auto craking')
    argparser.add_argument('--wallets', type=str,
                           help='directory for all wallets for autowallet', required=True)
    argparser.add_argument('--passlist ', type=str,
                           help='path to single wordlist', required=True)
    argparser.add_argument('--global_ws', type=str,
                           help='global words', required=True)
    args = argparser.parse_args()
    input_path = args.wallets
    passlist = args.passlist
    global_ws = args.global_ws
    if not os.path.isfile(passlist):
        print('The path specified does not exist')
        sys.exit()
    included_extensions = ['dat']
    file_names = [fn for fn in os.listdir(input_path)
                  if any(fn.endswith(ext) for ext in included_extensions)]
    for wallet in file_names:
        wallet = os.path.join(input_path, wallet)
        starting = f'telegram-send --pre "Starting {wallet} with wordlist {passlist}"'
        finished = f'telegram-send --pre "Finished {wallet} with {passlist}"'
        subprocess.run(starting, shell=True)
        command = f'python3 btcrecover.py --wallet {wallet} --passwordlist {passlist} --enable-opencl --dsw --enable-gpu'
        if(global_ws is not None):
            command += f' --global_ws {global_ws}'
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE)
        result = str(result.stdout.decode())
        if "Password found:" in result:
            sys.exit()
        subprocess.run(finished, shell=True)
print('All wordlist are checked')
sys.exit()
