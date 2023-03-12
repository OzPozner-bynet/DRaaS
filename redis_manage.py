import redis, requests
import re, json
import os
from functions import run_command_on_device_wo_close
from functions import change_interface_mode


redis_server = redis.Redis()
queue_name = "api_req_queue"
switch_info_url = "https://bynetprod.service-now.com/api/bdml/switch/getSwitchLogin"

def redis_set(KEY="",VALUE=""):
    redis_server.set(name=KEY, value=VALUE)
    key_val = redis_server.get(KEY)
    print(f"{KEY} : {key_val}")

def redis_queue_push(TASK):
    redis_server.rpush(queue_name, TASK)

def redis_queue_get():
    req = redis_server.lpop(queue_name)
    return req

if __name__ == "__main__":
    redis_queue_push(json.dumps(
{
    "result":
       {
            "command_number": "DRA0001010",
            "record_id": "fc1001ab8791a550220a98a83cbb35cc",
            "command": "",
            "switch": "2aa1ebb587571d905db3db1cbbbb359d",
            "switch_status": "on",
            "switch_ip": "192.168.88.30",
            "interface_name": "Gi0/9",
            "port_mode": "trunk",
            "dr_status": "Send_to_switch",
            "vlans": "60,61,62" # "1604,1282,201,202,203,204,205,206,207,208,209,1603,1604,154,155,156,998,1282,1283"
        }
}
).replace("\n", ""))
    redis_queue_push(json.dumps(
 {
     "result":
        {
             "command_number": "DRA0001011",
             "record_id": "fc1001ab8791a550220a98a83cbb35cc",
             "command": "",
             "switch": "2aa1ebb587571d905db3db1cbbbb359d",
             "switch_status": "on",
             "switch_ip": "192.168.88.30",
             "interface_name": "Gi0/10",
             "port_mode": "access",
             "dr_status": "Send_to_switch",
             "vlans": "" # "205,206,207,208,209,210214,215,216,217,218,222,1602,154,155,156,998,1282,1283"
         }
 }
 ).replace("\n", ""))
    redis_queue_push(json.dumps(
 {
     "result":
        {
             "command_number": "DRA0001012",
             "record_id": "fc1001ab8791a550220a98a83cbb35cc",
             "command": "",
             "switch": "2aa1ebb587571d905db3db1cbbbb359d",
             "switch_status": "on",
             "switch_ip": "192.168.88.30",
             "interface_name": "Gi0/11",
             "port_mode": "vlan",
             "dr_status": "Send_to_switch",
             "vlans": "64" # "205,206,207,218,222,1602,154,155,156"
         }
 }
 ).replace("\n", ""))
    redis_queue_push(json.dumps(
 {
     "result":
        {
             "command_number": "DRA0001013",
             "record_id": "fc1001ab8791a550220a98a83cbb35cc",
             "command": "show run",
             "switch": "2aa1ebb587571d905db3db1cbbbb359d",
             "switch_status": "on",
             "switch_ip": "192.168.88.30",
             "interface_name": "",
             "port_mode": "",
             "dr_status": "Send_to_switch",
             "vlans": "" # "205,206,207,218,222,1602,154,155,156"
         }
 }
 ).replace("\n", ""))

    q_len = redis_server.llen(queue_name)
    requests_list = redis_server.lrange(queue_name, 0, q_len)
    
    for req in requests_list:
        next_req = json.loads(re.sub("(^b\'|\'$)", "",str(redis_queue_get())))

        req_id = next_req["result"]["command_number"]
        req_vlans = next_req["result"]["vlans"]
        req_switch = next_req["result"]["switch"]
        req_switch_ip = next_req["result"]["switch_ip"]
        req_interface_name = next_req["result"]["interface_name"]
        req_port_mode = next_req["result"]["port_mode"]
        if next_req["result"]["command"] != "":
            req_cmd = next_req["result"]["command"]
        else:
            req_cmd = ""

        redis_set(req_id, "TO_DO")
        print("getting switch login info")
        switch_details = requests.post(switch_info_url, data=f"{{ 'switch_id': '{req_switch}' }}", 
                                       headers={'Content-Type': 'application/json'}, auth=('admin','Danut24680')).json()
        if switch_details['result'] != []:
            switch_user = "shapi" # switch_details['result'][0]['switch_username']
            switch_pass = "patish" # switch_details['result'][0]['switch_password']
            print(f"login into switch with:\nuser: {switch_user}\npass: {switch_pass}")
            
            if req_cmd != "":
                print(f"running: {req_cmd}")
                print(str(run_command_on_device_wo_close(req_switch_ip, switch_user, switch_pass, req_cmd)).replace('\\n', '\n').replace('\\r', '\r').replace("'!",""))
            else:
                print(f"working on request id: {req_id}, setting vlans: {req_vlans},for interface: {req_interface_name}, on switch: {req_switch}")
                change_interface_mode(req_switch_ip, switch_user, switch_pass, req_interface_name, req_port_mode, req_vlans)

        print(f"finish request id: {req_id} ")
        redis_set(req_id, "DONE")
        print("\n")

