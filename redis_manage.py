import redis
import re, json

redis_server = redis.Redis()
queue_name = "api_req_queue"

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
            "switch_ip": "192.168.128.65",
            "interface_name": "port-channel",
            "port_mode": "trunk",
            "dr_status": "Send_to_switch",
            "vlans": "1604,1282,201,202,203,204,205,206,207,208,209,1603,1604,154,155,156,998,1282,1283"
        }
}
).replace("\n", ""))
    redis_queue_push(json.dumps(
{
    "result":
       {
            "command_number": "DRA0001011",
            "record_id": "fc1001ab8791a550220a98a83cbb35cc",
            "command": "show run",
            "switch": "2aa1ebb587571d905db3db1cbbbb400d",
            "switch_status": "on",
            "switch_ip": "192.168.128.68",
            "interface_name": "mac-channel",
            "port_mode": "main",
            "dr_status": "Send_to_switch",
            "vlans": "205,206,207,208,209,210214,215,216,217,218,222,1602,154,155,156,998,1282,1283"
        }
}
).replace("\n", ""))
    redis_queue_push(json.dumps(
{
    "result":
       {
            "command_number": "DRA0001012",
            "record_id": "fc1001ab8791a550220a98a83cbb35cc",
            "command": "some costum cmd",
            "switch": "2aa1ebb587571d905db3db1cbbbb567f",
            "switch_status": "on",
            "switch_ip": "192.168.128.70",
            "interface_name": "vic-channel",
            "port_mode": "metro",
            "dr_status": "Send_to_switch",
            "vlans": "205,206,207,218,222,1602,154,155,156"
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
        req_cmd = ""
        if next_req["result"]["command"] != "":
            req_cmd = next_req["result"]["command"]

        redis_set(req_id, "TO_DO")
        print(f"working on request id: {req_id}, setting vlans: {req_vlans}, on switch: {req_switch}")
        if req_cmd:
            print(f"running: {req_cmd}")
        print(f"finish request id: {req_id} ")
        redis_set(req_id, "DONE")
        print("\n")