NULL = 0
from unittest import result
import settings
import requests
import json
import os
# parameters from .ini file
# date support
from datetime import datetime
# SSH support
import paramiko
from dotenv import load_dotenv

load_dotenv()

def run_command_on_device_wo_close(ip_address, username, password, command, sshClient=None):
    """ Connect to a device, run a command, and return the output."""
    # Load SSH host keys.
    if sshClient == None:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        # Add SSH host key when missing.
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        ssh = sshClient

    if 'DEFAULT' in settings.config:
        total_attempts = int(settings.config['DEFAULT']['total_ssh_attempts'])
    else:
        total_attempts = 1

    for attempt in range(total_attempts, settings.debug_level):
        try:
            if settings.debug_level > 5:
                print("Attempt to connect: %s" % attempt)
            # Connect to router using username/password authentication.
            ssh.connect(ip_address,
                        username=username,
                        password=password,
                        look_for_keys=False)
            # Run command.
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
            # Read output from command.
            output = ssh_stdout.readlines()
            # Close connection.
            # W/o close =># ssh.close()
            return output

        except Exception as error_message:
            if settings.debug_level > 2:
                print("Unable to connect")
                print(error_message)


def get_switch_ios(ip):
    """
    This function ssh with <switch_user>@ip to ip and runs 'show running config'
    """
    # TODO: fix to advance setup like https://networklessons.com/python/python-ssh
    if settings.debug_level > 0:
        print("sshing to: " + settings.switches_username + "@" + ip)
    sshClient = None
    if sshClient == None:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        # Add SSH host key when missing.
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        ssh = sshClient
    # login and run commands to get configuration
    #output = run_command_on_device_wo_close(ip, switches_username, switches_password, "enable", ssh)
    #if settings.debug_level > 5: print(output)
    #output = run_command_on_device_wo_close(ip, switches_username, switches_password, enable_password, ssh)
    #if settings.debug_level > 5: print(output)
    output = run_command_on_device_wo_close(
        ip, settings.switches_username, settings.switches_password, "terminal length 0", ssh)
    if settings.debug_level > 5:
        print(output)
    output = run_command_on_device_wo_close(
        ip, settings.switches_username, settings.switches_password, "show run", ssh)
    if settings.debug_level > 5:
        print(output)
    # Close connection.
    ssh.close()
    # write to file
    file_name = settings.base_path+"\\temp\\"+ip.replace(".", "_")+today()+".ios"
    f = open(file_name, "w")
    if output == None:
        output = ""
    else:
        for line in output:
            f.write(line.replace("\r", ""))
    f.close()


def get_JSON_from_IOS(filename):
    """
    This function transform filename_include_path_without_ext.ios to filename_include_path_without_ext.json
    """
    if settings.debug_level > 1:
        print("translate IOS to JSON for file: " + filename + ".ios")
    dissector = confparser.Dissector.from_file('ios.yaml')
    my_filename = filename+'.ios'
    myjson = str(dissector.parse_file(my_filename))
    if settings.debug_level > 15:
        print("creating File: " + my_filename +
              ".json  with data:\n" + myjson)
    with open(filename + '.json', "w") as myfile:
        myfile.write(myjson)

#from where the payload is comming?
def send_json_to_snow(payload):
    """
    This function sends Payload(JSON file) to SNOW API
    """
    if settings.debug_level > 1:
        print("sending JSON to snow: \n" + str(payload))
    response = requests.post(settings.url+"api/bdml/parse_switch_json/DRaaS/ParseSwitch", headers={
                             'Content-Type': 'application/json'}, auth=(settings.username, settings.password), json=payload)
    msg = "status is: " + str(response.status_code)
    if settings.debug_level > 1:
        print(msg)
        print(response.json())

#working
def get_commands_from_snow(hostname=None, ip=None):
    """
    This function gets commands from snow API
    """
    commandsUrl = settings.url + "api/bdml/parse_switch_json/GETCommands"
    if (ip != None):
        myparams = {"switch_ip": str(ip)}
    if (hostname != None):
        myparams = {"hostname": str(hostname)}
    if settings.debug_level > 1:
        print("getting commands from snow: hostname:" + str(hostname))
        print("getting commands from snow: ip:" + str(ip))
        print("getting commands from url:" + str(commandsUrl))

    response = requests.get(commandsUrl, headers={
                            'Content-Type': 'application/json'}, params=myparams, auth=(settings.username, settings.password))
    msg = "status is: " + str(response.status_code)
    myresponse = is_json(str(response.content)[2:-1])
    if settings.debug_level > 1:
       print(msg)
       if(myresponse):
          print('json response: ')
          print(response.json())
       else:
          print('none json response: ')
          print(str(response))
    if (response.status_code == 200 | response.status_code == 201):
      if(myresponse):
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

#working: brings the ips to take care
def get_ips_from_snow():
    """
    This function gets list of switchs ips from snow API
    """
    commandsUrl = settings.url + 'api/bdml/parse_switch_json/SwitchIPs'
    #

    response = requests.get(commandsUrl, headers={
                            'Content-Type': 'application/json'}, auth=(settings.username, settings.password))
    msg = "status is: " + str(response.status_code)
    #remove first two and last one
    print('my response is:' + str(response.content)[2:-1])
    myresponse = is_json(str(response.content)[2:-1])
    
    if settings.debug_level > 1:
        print(msg)
        if(myresponse):
          print('json response: ')
          print(response.json())

        else:
          print('none json response: ')
          print(str(response))
    if (response.status_code == 200 | response.status_code == 201):
      if(myresponse):
        myjson = json.loads(str(response.content)[2:-1])
        settings.ips = myjson["result"]["ips"]
        print(settings.ips)
      else:
          return 'error bad payload'
    else:
        return 'bad response from snow code:' + str(response.status_code) + ' message: ' + str(myresponse)
    #switch_username = myresponse["result"]["username"]
    #switch_password = myresponse["result"]["password"]
    #print(switch_username)
    #print(switch_password)


def set_status_to_sent(sysid):
    """
    This function sets status to sent
    """
    commandsUrl = settings.url + 'api/bdml/parse_switch_json/CommandSent'
    if (sysid != None):
        myparams = {"sysid": str(sysid)}
    if settings.debug_level > 1:
        print("getting commands from snow: sysid:" + str(sysid))

    response = requests.get(commandsUrl, headers={
                            'Content-Type': 'application/json'}, params=myparams, auth=(settings.username, settings.password))
    msg = "status is: " + str(response.status_code)
    if settings.debug_level > 1:
        print(msg)
        print(response.json())

#waiting to oz for switch
def send_commands_to_switch(ip, command):
    """
    This function sends commands to the switch
    """
   # get switch username and password from snow
    commandsUrl = settings.url + 'api/bdml/parse_switch_json/SwitchIPs'
    response = requests.get(commandsUrl, headers={
                            'Content-Type': 'application/json'}, auth=(settings.username, settings.password))
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
    # login and run commands to get configuration
    #output = run_command_on_device_wo_close(ip, switches_username, switches_password, "enable", ssh)
    #if settings.debug_level > 5: print(output)
    #output = run_command_on_device_wo_close(ip, switches_username, switches_password, enable_password, ssh)
    #if settings.debug_level > 5: print(output)
    output = run_command_on_device_wo_close(
        ip, settings.switches_username, settings.switches_password, "terminal length 0", ssh)
    if settings.debug_level > 5:
        print(output)
    output = run_command_on_device_wo_close(
        ip, settings.switches_username, settings.switches_password, "conf t", ssh)
    if settings.debug_level > 5:
        print(output)
    commands = command.split(",")
    for mycommand in commands:
        print("sending command: " + mycommand)
        output = run_command_on_device_wo_close(
            ip, settings.switches_username, settings.switches_password, mycommand, ssh)
        if settings.debug_level > 5:
            print(output)
    output = run_command_on_device_wo_close(
        ip, settings.switches_username, settings.switches_password, "end", ssh)
    output = run_command_on_device_wo_close(
        ip, settings.switches_username, settings.switches_password, "write", ssh)
    if settings.debug_level > 5:
        print(output)
    # Close connection.
    ssh.close()

#working
def today():
    now = datetime.now()
    date_time = now.strftime("_%m-%d-%Y-H-%H_")
    #date_time = "fix"
    return (date_time)


# run main
"""
data_json = {"hello": "world"}
payload = {'json_payload': data_json}
get_ips_from_snow()

for i in ips:
    ip=i.strip()
    print (ip)
    get_switch_ios(ip)
    filename = base_path+"\\temp\\"+ip.replace(".","_")+today()
    get_JSON_from_IOS(filename)
    JSON_file_name = base_path+"\\temp\\"+ip.replace(".","_")+today()+".JSON"
    f = open( JSON_file_name , "r")
    data_json = f.readlines()
    f.close()
    json = ''
    for line in data_json:
        json += line #.replace("\n","").replace('\"','"')
    #data_json = {"hello": "world"}
    payload = {'json_payload': json}
    
    send_json_to_snow(payload) 
"""
def parse_and_send_command(ip, command):
    match command:
      case 'get ios':
        ip=ip.strip()
        print ("command get ios for ip:"+ str(ip))
        #get_switch_ios(ip)
        filename = settings.base_path+"\\temp\\"+ip.replace(".","_")+today()
        # get_JSON_from_IOS(filename)
        #JSON_file_name = settings.base_path+"\\temp\\"+ip.replace(".","_")+today()+".JSON"
        # manual test:
        JSON_file_name = settings.base_path+"\\temp\\"+"spakim.json"
        f = open( JSON_file_name , "r")
        data_json = f.readlines()
        f.close()
        json = ''
        for line in data_json:
          json += line #.replace("\n","").replace('\"','"')
          #data_json = {"hello": "world"}
        payload = {'json_payload': json}
        #send_json_to_snow(payload) 
        response = send_json_to_snow(payload)
      case "pattern-2":
        response = send_commands_to_switch(ip = ip, command = command)
      case "pattern-3":
        response = send_commands_to_switch(ip = ip, command = command)
      case _:
        response = send_commands_to_switch(ip = ip, command = command)
    return response

def run():
   number_of_runs = 1
   for x in range(number_of_runs):
    print(get_ips_from_snow())
    for ip in settings.ips:
     print('current ip is: ' + ip.strip())
     commands = get_commands_from_snow(ip=ip.strip())
     if type(commands) is str:
         response = parse_and_send_command(ip,commands)
     else:
        for command in commands:
         response = parse_and_send_command(ip,command)
   else:
    print("Finally finished!")
    
   #get_commands_from_snow(hostname='YanirServer')
   #get_ips_from_snow()
   #send_json_to_snow()
   #set_status_to_sent('f49bffa3878b9d505db3db1cbbbb351e')
    #send_commands_to_switch(ip="10.10.20.48", command="hostname yanir")


if __name__ == "__main__":
    run()
