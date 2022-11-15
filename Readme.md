
if facing certificate issues:

Locate your pip.conf file based on your operating system -

1. MacOS - $HOME/Library/Application Support/pip/pip.conf

2. Unix - $HOME/.config/pip/pip.conf

3. Windows - %APPDATA%\pip\pip.ini

Open the pip.conf file and add trusted-host under the global param -

[global]
trusted-host = pypi.python.org
               pypi.org
               files.pythonhosted.org


Restart your python and then the pip installer will trust these hosts permanently.



**Windows**

install python from cmd shell type:
`python` and MS store shall popup, select python3 and click get/install.
After python is install install pip: by typing in cmd shell 
`python.exe -m pip install --upgrade pip`
after pip is installed from command shell type: 

`pip install -U python-dotenv requests configparser paramiko confparser`
removed sys windows-curses

you can navigate to control panel > System and Security > System > Advanced system Settings.
Now in Advance System Setting click on Environment Variables.
Here we can add new user variables and new system variables. We will add user variable by clicking New under user variables.

In the new window you can add Variable name and Variable value and click ok.
Now, click Ok on Environment Variables window to save changes.

**Linux**

Start by updating the package list using the following command: `sudo apt update`.
Use the following command to install pip for Python 3: `sudo apt install python3-pip`. ...
Once the installation is complete, verify the installation by checking the pip version: `pip3 --version`.
`pip3 install -U python-dotenv requests configparser paramiko  confparser`
removed sys curses

nano ~/.bash_profile
export USER="username"
export PASSWORD="password"


**Setup Paramters**

cd ./config/
cp/copy parameters.ini.example parameters.ini
edit parameters.ini with users/password/IPs

**Execute**
from shell run `python main.py`
