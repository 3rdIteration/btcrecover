import sys
import subprocess
import time


if __name__ == '__main__':
    subprocess.run('export PATH=$PATH:~/.local/bin', shell=True)
    path = subprocess.run('echo $PATH', shell=True, stdout=subprocess.PIPE)
    path = (path.stdout.decode()).split(':')
    path = path[len(path) - 1]
    local = subprocess.run('echo ~/.local/bin',
                           shell=True, stdout=subprocess.PIPE)
    local = local.stdout.decode()
    print(f'path -> {path}\nlocal -> {local}')
    if(path == local):
        print('~/.local/bin added to path')
        print('Installing....')
        time.sleep(2)
        subprocess.run('sudo apt-get clean', shell=True)
        subprocess.run('sudo apt-get update', shell=True)
        subprocess.run(
            'sudo apt-get install -y python3 python3-pip python3-dev git', shell=True)
        subprocess.run(
            'wget https://developer.download.nvidia.com/compute/cuda/12.9.1/local_installers/cuda_12.9.1_575.57.08_linux.run', shell=True)
        subprocess.run(
            'sudo sh cuda_12.9.1_575.57.08_linux.run', shell=True)
        subprocess.run('pip3 install -r requirements.txt', shell=True)
        subprocess.run('clear', shell=True)
        print('Enter you telegram bot token search @Botfather in telegram')
        subprocess.run('telegram-send --configure', shell=True)
        subprocess.run(
            'telegram-send --pre "Yoo boi you are good to go we will alert you on your progress\nYou can send message to your bot by telegram-send --pre message"', shell=True)
        sys.exit()
    else:
        print('Run this command to continue\nexport PATH=$PATH:~/.local/bin')
        time.sleep(2)
        sys.exit()
