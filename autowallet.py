import os
import sys
import argparse
import subprocess


global_ws = '171032'
pwd = os.getcwd()


if __name__ == "__main__":
    password = ''
    argparser = argparse.ArgumentParser(
        description='Set wallet on auto craking')
    argparser.add_argument('--wallets', type=str,
                           help='directory for all wallets for autowallet', required=True)
    argparser.add_argument('--passlist ', type=str,
                           help='path to single wordlist', required=True)
    args = argparser.parse_args()
    input_path = args.wallets
    passlist = args.passlist
    if not os.path.isdir(pwd + '\\' + input_path):
        print(pwd + input_path)
        print('The path specified does not exist')
        sys.exit()
    included_extensions = ['dat']
    file_names = [fn for fn in os.listdir(input_path)
                  if any(fn.endswith(ext) for ext in included_extensions)]
    for wallet in file_names:
        wordlist = input_path + '/' + wallet
        command = f'python3 btcrecover.py --wallet {wallet} --passwordlist {passlist} --enable-opencl --dsw --enable-gpu --global-ws {global_ws}'
        subprocess.run(command)
print('All wordlist are checked')
sys.exit()
