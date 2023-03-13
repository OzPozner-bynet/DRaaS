import redis, requests
import re, json
import os, time
from functions import run_command_on_device_wo_close
from functions import change_interface_mode


redis_server = redis.Redis()
queue_name = "api_req_queue"
snow_url = "https://bynetprod.service-now.com/api/bdml/switch"
switch_info_url = snow_url+"/getSwitchLogin"
get_cmds_url = snow_url+"/getCommands"
update_req_url = snow_url+"/SetCommandStatus"

def redis_set(KEY="",VALUE=""):
    redis_server.set(name=KEY, value=VALUE)
    # key_val = redis_server.get(KEY)
    # print(f"{KEY} : {key_val}")

def get_requests():
    commands = requests.post(get_cmds_url, headers={'Content-Type': 'application/json'}, auth=('admin','Danut24680')).json()
    return commands['result']

def send_status_update(ID, STATUS, OUTPUT):
    payload = json.dumps(
{
    "command_id": f"{ID}",
    "command_status": f"{STATUS}",
    "command_output": f"{OUTPUT}"
}
    )
    print(payload)
    answer = requests.post(update_req_url, data=payload, 
                    headers={'Content-Type': 'application/json'}, auth=('admin','Danut24680'))
    print(answer.json())

def redis_queue_push(TASKS):
    for TASK in TASKS:
        if bool(re.search('(active|failed)', TASK["dr_status"])):
            redis_server.rpush(queue_name, str(TASK))

def redis_queue_get():
    req = redis_server.lpop(queue_name)
    return req

def json_parser(to_parse):
    first_setup = to_parse.replace('\\n', '\n').replace('\\r', '\r').replace("'!","")
    clean = re.sub("(\'|\,)", "", first_setup)
    if re.search(r'(^\[|\]$)', clean):
        switch_braces = re.sub("\]$","}",re.sub("^\[","{",clean))

    formated = ""

    empty_lines = 0
    for e_line in switch_braces.splitlines():
        if len(re.findall(r'\w+', e_line)) == 1 or len(re.findall(r'\w+\-\w+\-?\w?', e_line)) == 1 or not e_line.strip():
            empty_lines+=1
    num_of_lines = len(switch_braces.splitlines()) - empty_lines
    line_num = 1
    for line in switch_braces.splitlines():
        if len(re.findall(r'\w+\-\w+\-?\w?', line)) == 1:
            continue
        if len(re.findall(r'\w+', line)) == 1 or not line.strip():
            continue
        if line_num == 1:
            formated = line+'\n'
            line_num+=1
            continue
        formated1 = re.sub("(^\s+)(?=\w)", r'\1"', line,)
        formated2 = re.sub("(\w)(?=\s)", r'\1":', formated1, 1)
        if line_num == (num_of_lines-1):
            formated3 = re.sub("(?<=\s)(\w.*)", r'"\1"\n', formated2, 1)
        else:
            formated3 = re.sub("(?<=\s)(\w.*)", r'"\1",\n', formated2, 1)
        line_num+=1
        formated = formated+formated3
    parsed_json = json.loads(formated)
    return parsed_json



if __name__ == "__main__":
    while True:
        redis_queue_push(get_requests())

        q_len = redis_server.llen(queue_name)
        requests_list = redis_server.lrange(queue_name, 0, q_len)

        for req in requests_list:
            next_req = re.sub("(^b\"|\"$)", "",str(redis_queue_get()))
            fix_quotes = re.sub("'", "\"", next_req)
            no_none = re.sub("None", "\"\"", fix_quotes)
            json_req = json.loads(no_none)

            req_id = json_req["record_id"]
            req_vlans = json_req["vlans"]
            req_switch = "2aa1ebb587571d905db3db1cbbbb359d" # json_req["switch"]
            req_switch_ip = "192.168.88.30" # json_req["switch_ip"]
            req_interface_name = json_req["interface_name"]
            req_port_mode = json_req["port_mode"]
            if json_req["command"] != "":
                req_cmd = json_req["command"]
            else:
                req_cmd = ""
            
            task_sts = redis_server.get(req_id)
            if task_sts == None:
                redis_set(req_id, "active")
                task_sts = redis_server.get(req_id)

            if "active" in str(task_sts):
                switch_details = requests.post(switch_info_url, data=f"{{ 'switch_id': '{req_switch}' }}", 
                                    headers={'Content-Type': 'application/json'}, auth=('admin','Danut24680')).json()
    #     if switch_details['result'] != []:
                switch_user = "shapi" # switch_details['result'][0]['switch_username']
                switch_pass = "patish" # switch_details['result'][0]['switch_password']
            
                try:
                    if req_cmd != "" and req_port_mode == "":
                        output = json_parser(str(run_command_on_device_wo_close(req_switch_ip, switch_user, switch_pass, req_cmd)))
                    else:
                        output = str(change_interface_mode(req_switch_ip, switch_user, switch_pass, req_interface_name, req_port_mode, req_vlans))
                except Exception as error:
                    send_status_update(req_id, "failed", error)
                else:
                    redis_set(req_id, "completed")
                    task_sts = re.sub("(^b\'|\'$)", "",str(redis_server.get(req_id)))
                    send_status_update(req_id, task_sts, output)
            elif "completed" in str(task_sts):
                continue

        time.sleep(10)
            
