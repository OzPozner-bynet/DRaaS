import redis, requests
import re, json, sys, dotenv
from time import sleep
from functions import run_command_on_device_wo_close
from functions import change_interface_mode


redis_server = redis.Redis()
queue_name = "api_req_queue"
snow_url = "https://bynetprod.service-now.com/api/bdml/switch"
switch_info_url = "https://bynetprod.service-now.com/api/bdml/parse_switch_json/SwitchIPs"
get_cmds_url = snow_url+"/getCommands"
update_req_url = snow_url+"/SetCommandStatus"

def redis_set(KEY="",VALUE="",OUTPUT=""):
    OUTPUT = re.sub("\"","\\\"","      ".join(OUTPUT.splitlines()))
    redis_server.set(name=KEY, value=f'{{ "status": "{VALUE}", "output": "{OUTPUT}" }}')
    # print(redis_server.get(KEY))

def redis_queue_get():
    req = redis_server.lpop(queue_name).decode()
    return req

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

def json_parser(to_parse):
    decode = to_parse.decode()
    # first_setup = to_parse.replace('\\n', '\n').replace('\\r', '\r').replace("'!","")
    # clean = re.sub("(\'|\,|b\')", "", first_setup)

    if re.search(r'(^\[|\]$)', decode):
        formated = ""

        switch_braces = re.sub("\]$","}",re.sub("^\[","{",decode))

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
        parsed = json.loads(formated)
    else:
        parsed = decode.replace("!","")
    return parsed



if __name__ == "__main__":
    while True:
        q_len = redis_server.llen(queue_name)
        requests_list = redis_server.lrange(queue_name, 0, q_len)

        for req in requests_list:
            next_req = redis_queue_get()
            fix_quotes = re.sub("'", "\"", next_req)
            no_none = re.sub("None", "\"\"", fix_quotes)
            json_req = json.loads(no_none)

            req_id = json_req["record_id"]
            req_vlans = json_req["vlans"]
            req_switch = "2aa1ebb587571d905db3db1cbbbb359d" # json_req["switch"]
            req_switch_ip = json_req["switch_ip"]
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
                switch_details = requests.get(switch_info_url, data=f"{{ 'switch_id': '{req_switch}' }}", 
                                    headers={'Content-Type': 'application/json'}, auth=('admin','Danut24680')).json()
                

                len1 = len(switch_details['result'])

                for i in range(len1):
                    if(switch_details['result'][i]['ip'] == req_switch_ip):
                        print("username: " + switch_details['result'][i]['username'] + ", password: " + switch_details['result'][i]['password'])
                    
            
                try:
                    if req_cmd != "" and req_port_mode == "":
                        if req_interface_name != "":
                            output = json_parser(run_command_on_device_wo_close(req_switch_ip, switch_user, switch_pass, req_cmd+" "+req_interface_name))
                        else:
                            output = json_parser(run_command_on_device_wo_close(req_switch_ip, switch_user, switch_pass, req_cmd))
                    else:
                        output = change_interface_mode(req_switch_ip, switch_user, switch_pass, req_interface_name, req_port_mode, req_vlans)
                except Exception as error:
                    send_status_update(req_id, "failed", error)
                else:
                    redis_set(req_id, "completed", output)
                    task_sts = json.loads(redis_server.get(req_id).decode())["status"]
                    send_status_update(req_id, task_sts, output)
                    
            #elif: "completed" in str(task_sts):
                continue
        
    sleep(10)

