import subprocess
from typing_extensions import TypeGuard

if __name__ == '__main__':
    subprocess.run('sudo apt-get clean', shell=True)
    subprocess.run('sudo apt-get update', shell=True)
    subprocess.run(
        'sudo apt-get install -y python3 python3-pip python3-dev git', shell=True)
    subprocess.run(
        'wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/cuda-ubuntu2004.pin', shell=True)
    subprocess.run(
        'sudo mv cuda-ubuntu2004.pin /etc/apt/preferences.d/cuda-repository-pin-600', shell=True)
    subprocess.run(
        'sudo apt-key adv --fetch-keys https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/7fa2af80.pub', shell=True)
    subprocess.run(
        'sudo add-apt-repository "deb https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/ /"', shell=True)
    subprocess.run('sudo apt-get update', shell=True)
    subprocess.run('sudo apt-get -y install cuda', shell=True)
    subprocess.run('pip3 install -r requirements.txt')
    localDir = subprocess.run('cd ~/.local/bin ; pwd', shell=True, stdout=True)
    subprocess.run(f'export PATH=$PATH:{localDir}', shell=True)
    subprocess.run('telegram-send --configure', shell=True)
    subprocess.run(
        'telegram-send --pre "Yoo boi you are good to go we will alert you on your progress\nYou can send message to your bot by telegram-send --pre message"')
    exit()
