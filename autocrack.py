import os
import sys
import argparse
import glob
import subprocess


global_ws = '171032'
pwd = os.getcwd()


if __name__ == "__main__":
    password = ''
    argparser = argparse.ArgumentParser(
        description='Set wallet on auto craking')
    argparser.add_argument('--wallet', type=str,
                           help='wallet file to crack', required=True)
    argparser.add_argument('--password', type=str,
                           help='path to wordlist', required=True)
    args = argparser.parse_args()
    input_path = args.password
    wallet = args.wallet
    if not os.path.isdir(pwd + '\\' + input_path):
        print(pwd + input_path)
        print('The path specified does not exist')
        sys.exit()
    included_extensions = ['txt']
    file_names = [fn for fn in os.listdir(input_path)
                  if any(fn.endswith(ext) for ext in included_extensions)]
    for wordlist in file_names:
        wordlist = input_path + '/' + wordlist
        command = f'python3 btcrecover.py --wallet {wallet} --passwordlist {wordlist} --enable-opencl --dsw --enable-gpu --global-ws {global_ws}'
        subprocess.run(command)
print('All wordlist are checked')
sys.exit()
