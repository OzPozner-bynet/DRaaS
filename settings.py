import configparser
import os 

def init():
    global debug_level
    global username
    global password
    global url
    global base_path
    global ips
    global switches_username
    global switches_password
    debug_level = 0
    global config
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
        url = "https://bynetdev.service-now.com/"
        #api/bdml/parse_switch_json/DRaaS/ParseSwitch

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

    if int(debug_level) > 8:
        print("Today:", today(), "\n")
        print("url: ", url, "\n")
        print("username: ", username, "\n")
        print("password: ", password, "\n")
        print("Switches IP", ips, "\n")