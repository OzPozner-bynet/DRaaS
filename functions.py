NULL = 0
import time, sys, threading
from unittest import result
import requests, json, re, os
from datetime import datetime
import paramiko, configparser, confparser
from ntc_templates.parse import parse_output
from netmiko import ConnectHandler
import json
from dotenv import load_dotenv
from socket import *
import glv
from glv import added_vlan  # Import the added_vlan list
load_dotenv()

config = configparser.ConfigParser()
config.sections()
config.read('./config/parameters.ini')

class SSHClient:
    def __init__(self, address, username, password):
        print("Connecting to server on IP", str(address) + ".")
        self.connection_params = {
            'device_type': 'cisco_ios',
            'ip': address,
            'username': username,
            'password': password,
        }
        self.connection = None

    def connect(self):
        self.connection = ConnectHandler(**self.connection_params)
        self.connection.enable()

    def close_connection(self):
        if self.connection:
            self.connection.disconnect()

    def exec_command(self, command, use_textfsm=False, expect_string=None):
        if self.connection:
            if use_textfsm:
                output = self.connection.send_command(command, use_textfsm=True, expect_string=expect_string)
            else:
                output = self.connection.send_command(command, expect_string=expect_string)
            return output
        else:
            raise ValueError("SSH connection is not established.")

class ssh_new:
    shell = None
    client = None
    transport = None

    def __init__(self, address, username, password):
        print("Connecting to server on ip", str(address) + ".")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
        self.client.connect(address, username=username, password=password, look_for_keys=False)

    def close_connection(self):
        if(self.client != None):
            self.client.close()

    def open_shell(self):
        self.shell = self.client.invoke_shell()


    def exec_command(self, command):
        _, ssh_stdout, ssh_stderr = self.client.exec_command(command)
        err = ssh_stderr.readlines()
        return err if err else ssh_stdout.readlines()

    def send_shell(self, command):
        if(self.shell):
            return self.shell.send(command + "\n")
        else:
            print("Shell not opened.")

def run_command_and_get_json(ip_address, username, password, command):
    # Create an instance of the SSHClient class
    ssh_client = SSHClient(ip_address, username, password)
    try:
        # Establish the SSH connection
        ssh_client.connect()
        if 'show run' in command:
            output = ssh_client.exec_command(command)
            parsed_data = confparser.Dissector.from_file('ios.yaml').parse_str(output)
            json_data = json.dumps(parsed_data, indent=4)
        else:
            output = ssh_client.exec_command(command, use_textfsm=True)
            json_data = json.dumps(output, indent=2)

        return json_data

    except (paramiko.AuthenticationException, paramiko.SSHException) as error:
        # Raise an exception if there is an error during the connection
        raise error

    finally:
        # Close the SSH connection when done
        ssh_client.close_connection()

def set_switch_interface(ip_address,interface, ifaceStatus="enable"):
    """
    This function ssh with <switch_user>@ip to ip and change the status of interface
    """
    print("sshing to: " + switch_user + "@" + ip_address)
    change_interface_mode(ip_address, "shapi", "patish", None, "interface="+interface, "status=disable")


def send_json_to_snow(payload):
    """
    This function sends Payload(JSON file) to SNOW API
    """
    print("sending JSON to snow:\n" + str(payload))
    response = requests.post(
        settings.url + "api/bdml/parse_switch_json/DRaaS/ParseSwitch",
        headers={'Content-Type': 'application/json'},
        auth=(switch_user, switch_password),
        json=payload
    )
    msg = "status is: " + str(response.status_code)
    print(msg)
    print(response.json())


def get_commands_from_snow(hostname=None, ip=None):
    """
    This function gets commands from snow API
    """
    commandsUrl = "https://bynetprod.service-now.com/api/bdml/switch" + "/getCommands"
    myparams = None

    if ip is not None:
        myparams = {"switch_ip": str(ip)}
    if hostname is not None:
        myparams = {"hostname": str(hostname)}

    print("getting commands from snow: hostname:" + str(hostname))
    print("getting commands from snow: ip:" + str(ip))
    print("getting commands from url:" + str(commandsUrl))

    response = requests.get(commandsUrl, headers={'Content-Type': 'application/json'}, params=myparams, auth=(switch_user, switch_password))

    msg = "status is: " + str(response.status_code)
    myresponse = is_json(str(response.content)[2:-1])
    print(msg)
    
    if(myresponse):
        print('json response: ')
        print(response.json())
    else:
        print('none json response: ')
        print(str(response))

    
    if response.status_code in [200,201]:
      if myresponse:
        myjson = json.loads(str(response.content)[2:-1])['result']
        if not myjson['commands']:
            return []
        else:
            print(myjson['commands'][0]['command'])
            return myjson['commands'][0]['command']
      else:
          return 'error bad payload'
    else:
        return 'bad response from snow code:' + str(response.status_code) + ' message: ' + str(myresponse)


def is_json(myjson):
  try:
    json.loads(str(myjson))
  except ValueError as e:
    return False
  return True


def get_ips_from_snow():
    """
    This function gets list of switchs ips from snow API
    """
    commandsUrl = "https://bynetprod.service-now.com/api/bdml/switch" + 'SwitchIPs'

    response = requests.get(commandsUrl, headers={'Content-Type': 'application/json'}, auth=(switch_user, switch_password))

    msg = "status is: " + str(response.status_code)
    
    response_content = str(response.content)[2:-1]
    print('my response is: ' + response_content)
    is_json_response = is_json(response_content)

    if is_json_response:
        print(msg)
        print('json response: ')
        jsonResponse = json.loads(response_content)
        print(jsonResponse)
        print("##########")
        result = jsonResponse.get("result", [])
        for item in result:
            print(item['ip'])
            print(item['username'])
            print(item['password'])
    else:
        return 'error bad payload'
    
    if response.status_code in [200, 201]:
        return 'Success'
    else:
        return 'bad response from SNOW code:' + str(response.status_code) + ' message: ' + str(is_json_response)


def set_status_to_sent(sysid):
    """
    This function sets status to sent
    """
    commandsUrl = "https://bynetprod.service-now.com/api/bdml/switch" + "/SetCommandStatus"
    if (sysid != None):
        myparams = {"sysid": str(sysid)}
    print("getting commands from snow: sysid:" + str(sysid))

    response = requests.get(commandsUrl, headers={'Content-Type': 'application/json'}, params=myparams, auth=(switch_user, switch_password))
    msg = "status is: " + str(response.status_code)
    print(msg)
    print(response.json())


def send_commands_to_switch(ip, command):
    """
    This function sends commands to the switch
    """
   # get switch username and password from snow
    commandsUrl = "https://bynetprod.service-now.com/api/bdml/parse_switch_json/SwitchIPs"
    response = requests.get(commandsUrl, headers={'Content-Type': 'application/json'}, auth=(switch_user, switch_password))
    myresponse = response.json()
    ips = myresponse["result"]["ips"]
    for myip in ips:
        if myip == ip:
            switch_username = myresponse["result"]["username"]
            switch_password = myresponse["result"]["password"]
            if settings.debug_level > 0:
                print("sendig command "+command+" to: " +
                      settings.switches_username + "@" + ip)
                print(switch_username)
                print(switch_password)
    sshClient = None
    if sshClient == None:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        # Add SSH host key when missing.
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        ssh = sshClient
    output = run_command_and_get_json(ip, settings.switches_username, settings.switches_password, "terminal length 0", ssh)
    print(output)
    output = run_command_and_get_json(ip, settings.switches_username, settings.switches_password, "conf t", ssh)
    print(output)
    commands = command.split(",")
    for mycommand in commands:
        print("sending command: " + mycommand)
        output = run_command_and_get_json(ip, switch_username, settings.switches_password, mycommand, ssh)
        if settings.debug_level > 5:
            print(output)
    output = run_command_and_get_json(ip, switch_username, settings.switches_password, "end", ssh)
    output = run_command_and_get_json(ip, switch_username, settings.switches_password, "write", ssh)
    print(output)
    # Close connection.
    ssh.close()

def today():
    now = datetime.now()
    date_time = now.strftime("_%m-%d-%Y-H-%H_")
    #date_time = "fix"
    return (date_time)

def get_interfaces_mode(ip_address, username, password, interfaces, sshClient=None):
    interfaces_mode = []
    for interface in interfaces:
        command = "show int " + interface + " switchport | include Administrative Mode:"
        response = run_command_and_get_json(ip_address, username, password,command, sshClient)[0]
        interface_mode = str(response.replace("\n", "").replace("\r", "").replace("Administrative Mode: ", ""))
        interface_mode = {
            'interface': interface,
            'mode': interface_mode
        }
        interfaces_mode.append(interface_mode)
    return interfaces_mode

def check_privileged_connection(connection):
    buffer_size = 4096
    def flush(connection):
        while connection.shell.recv_ready():
            connection.shell.recv(buffer_size)
    def get_prompt(connection):
        flush(connection)  # flush everything from before
        connection.shell.sendall('\n')

        time.sleep(.3)
        data = str(connection.shell.recv(buffer_size), encoding='utf-8').strip()
        flush(connection)  # flush everything after (just in case)

        return data
    prompt = get_prompt(connection)
    return True if prompt[-1] == '#' else False

def get_all_interfaces(ip_address, username, password):
    interfaces = run_command_and_get_json(ip_address, username, password, 'show int switchport | include Name',ssh_new)
    for idx, interface in enumerate(interfaces):
        interfaces[idx] = interface.split()[1]
    return interfaces

def check_vlan_exists(ip_address, username, password, vlan_id):
    response = run_command_and_get_json(ip_address, username, password, f'show vlan id {vlan_id}')
    if "not found in current VLAN database" in response:
        print(f"VLAN {vlan_id} not found. Creating the VLAN...")
        create_vlan_command = f'vlan {vlan_id}'
        run_command_and_get_json(ip_address, username, password, create_vlan_command)
        print(f"VLAN {vlan_id} created.")
        added_vlan.append(vlan_id)  # Append the VLAN ID to the list of added VLANs in glv
        return True
    else:
        print(f"VLAN {vlan_id} already exists.")
        return True  # The VLAN exists


def change_interface_mode(ip_address, username, password, interface, mode, vlan_range, enable_pass=None):
    connection = ssh_new(ip_address, username, password)
    try:
        connection.open_shell()
        time.sleep(1)

        if not check_privileged_connection(connection):
            if enable_pass is not None:
                connection.send_shell('enable')
                time.sleep(1)
                connection.send_shell(enable_pass)
                time.sleep(1)
            else:
                raise ValueError('enable_pass is missing, and SSH connection is not privileged')

        connection.send_shell('conf terminal')
        time.sleep(1)
        connection.send_shell(f'interface {interface}')
        time.sleep(1)

        # Remove any existing configuration related to the opposite mode
        if mode == 'trunk':
            connection.send_shell('no switchport access vlan')
            connection.send_shell('no switchport mode access')
            connection.send_shell('switchport trunk encapsulation dot1q')
            connection.send_shell('switchport mode trunk')
            
            vlan_ids = []

            for vlan_group in vlan_range.split(','):
                if "-" in vlan_group:
                    start_vlan, end_vlan = map(int, vlan_group.split('-'))
                    vlan_ids.extend(range(start_vlan, end_vlan + 1))
                else:
                    vlan_ids.append(int(vlan_group))

            for vlan_id in vlan_ids:
                if check_vlan_exists(ip_address, username, password, vlan_id) == False:
                    raise ValueError(f'VLAN {vlan_id} is missing in device configuration')
                connection.send_shell(f'switchport trunk allowed vlan add {vlan_id}')
            
            print(f'Interface {interface} mode changed to trunk, allowed VLANs: {vlan_range}')
        elif mode == 'access':
            connection.send_shell('no switchport trunk encapsulation dot1q')
            connection.send_shell('no switchport mode trunk')
            
            if "-" in vlan_range:
                raise ValueError("VLAN range is not supported in access mode")
            elif vlan_range:
                vlan_id = int(vlan_range)
                if check_vlan_exists(ip_address, username, password, vlan_id) == False:
                    raise ValueError(f'VLAN {vlan_id} is missing in device configuration')
                connection.send_shell(f'switchport access vlan {vlan_id}')
            
            print(f'Interface {interface} mode changed to access, VLAN: {vlan_range}')
            connection.send_shell('no switchport trunk allowed vlan')  # Remove trunk allowed VLANs
        
        connection.send_shell('exit')
        connection.send_shell('exit')
        connection.send_shell('write memory')  # Save the configuration to memory
        time.sleep(10)  # Give it some time to save the configuration
        connection.close_connection()

    except (paramiko.AuthenticationException, paramiko.SSHException) as error:
        # Raise an exception if there is an error during the connection
        raise error

