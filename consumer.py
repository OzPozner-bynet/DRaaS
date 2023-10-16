import redis, requests
import re, json, sys, dotenv
from time import sleep
from functions import run_command_and_get_json
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
    print(redis_server.get(KEY))

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
    answer = requests.post(update_req_url, data=payload, headers={'Content-Type': 'application/json'}, auth=('admin','Danut24680'))

if __name__ == "__main__":
    while True:
        q_len = redis_server.llen(queue_name)
        print(f'Queue length: {q_len}')
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
                switch_details = requests.get(switch_info_url, data=f"{{ 'switch_id': '{req_switch}' }}", headers={'Content-Type': 'application/json'}, auth=('admin','Danut24680')).json()

                for i in range(len(switch_details['result'])):
                    if(switch_details['result'][i]['ip'] == req_switch_ip):
                        switch_user=switch_details['result'][i]['username']
                        switch_password=switch_details['result'][i]['password']
                    
                try:
                    if req_cmd != "" and req_port_mode == "":
                        if req_interface_name != "":
                            output = run_command_and_get_json(req_switch_ip, switch_user, switch_password, req_cmd+" "+req_interface_name)
                        else:
                            output = run_command_and_get_json(req_switch_ip, switch_user, switch_password, req_cmd)
                    else:
                        output = change_interface_mode(req_switch_ip, switch_user, switch_password, req_interface_name, req_port_mode, req_vlans)
                except Exception as error:
                    send_status_update(req_id, "failed", error)
                else:
                    redis_set(req_id, "completed", output)
                    task_sts = json.loads(redis_server.get(req_id).decode())["status"]
                    send_status_update(req_id, task_sts, output)
                    
            elif "completed" in str(task_sts):
                continue
        
        sleep(10)

