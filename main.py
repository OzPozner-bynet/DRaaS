
NULL = 0
from collections.abc import Mapping
# import requests
import json
# parameters from ENV
from dotenv import load_dotenv   #for python-dotenv method
load_dotenv()                    #for python-dotenv method
import os 
# parameters from .ini file
import configparser
#date support
from datetime import datetime
#SSH support
import paramiko
#adding conf parser
import sys
import confparser
from functions import run
from functions import today
from functions import get_commands_from_snow


load_dotenv()

global debug_level
debug_level = 0
config = configparser.ConfigParser()
config.sections()
config.read('./config/parameters.ini')

if 'DEFAULT' in config:
    debug_level = int(config['DEFAULT']['debug_level'])
else:
    debug_level = 0

if "DEFAULT" in config:
    url = config["DEFAULT"]['Url']
else:
    url = "https://bynetdev.service-now.com/api/bdml/parse_switch_json/DRaaS/ParseSwitch"

if "DEFAULT" in config:
    username = config['DEFAULT']['username']
else:
    username = os.environ.get('USER')

if "DEFAULT" in config:
    password = config['DEFAULT']['password']
else:
    password = os.environ.get('password')

if "DEFAULT" in config:
    base_path = config['DEFAULT']['basepath']
else:
    base_path = "."

if "DEFAULT" in config:
    enable_password = config['DEFAULT']['enable_password']
else:
    enable_password = os.environ.get('enable_password')

if "SWITCHES" in config:
    ips = config['SWITCHES']['ips'].split(",")
    switches_username = config['SWITCHES']['username']
    switches_password = config['SWITCHES']['password']
else:
    ips = os.environ.get('ips').split(",")
    switches_username = os.environ.get('switches_username')
    switches_password = os.environ.get('switches_password')

if int(debug_level) > 2:
    print("Today:", today(), "\n")
    print("url: ", url, "\n")
    print("username: ", username, "\n")
    print("password: ", password, "\n")
    print("Switches IP", ips, "\n")

#get_commands_from_snow(hostname='YanirServer',ip='none', url)

if __name__ == "__main__":
    run()
    #get_commands_from_snow(hostname='YanirServer', url)

