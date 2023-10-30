import redis, requests
import re, json, sys, dotenv
from time import sleep, time
from functions import run_command_and_get_json
from functions import change_interface_mode
from functions import check_vlan_exists
import glv
from glv import added_vlan

redis_server = redis.Redis()
queue_name = "api_req_queue"
snow_url = "https://bynetprod.service-now.com/api/bdml/switch"
switch_info_url = "https://bynetprod.service-now.com/api/bdml/parse_switch_json/SwitchIPs"
get_cmds_url = snow_url + "/getCommands"
update_req_url = snow_url + "/SetCommandStatus"

credential_dict = {}

def redis_set(KEY="", VALUE="", OUTPUT=""):
    if OUTPUT:
        OUTPUT = re.sub("\"", "\\\"", "      ".join(OUTPUT.splitlines()))
    else:
        OUTPUT = ""  # Handle the case where OUTPUT is None or empty
    redis_server.set(name=KEY, value=f'{{ "status": "{VALUE}", "output": "{OUTPUT}" }}')
    #print(redis_server.get(KEY))

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
    answer = requests.post(update_req_url, data=payload, headers={'Content-Type': 'application/json'}, auth=('admin', 'Danut24680'))

def update_credential_dict(ip, username, password, status):
    timestamp = time()
    credential_dict[ip] = {
        "timestamp": timestamp,
        "status": status,
        "user": username,
        "pass": password
    }

def get_credentials(ip):
    if ip in credential_dict:
        credential = credential_dict[ip]
        if credential["status"] == "success":
            return credential["user"], credential["pass"]
    return None, None

def main():
    glv.added_vlan  # Declare that we are using the global variable
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
            req_switch = "2aa1ebb587571d905db3db1cbbbb359d"  # json_req["switch"]
            req_switch_ip = json_req["switch_ip"]
            req_interface_name = json_req["interface_name"]
            req_port_mode = json_req["port_mode"]
            if json_req["command"] != "":
                req_cmd = json_req["command"]
            else:
                req_cmd = ""

            task_sts = redis_server.get(req_id)
            if task_sts is None:
                redis_set(req_id, "active")
                task_sts = redis_server.get(req_id)

            if "active" in str(task_sts):
                switch_user = None
                switch_password = None
                switch_details = requests.get(switch_info_url, data=f"{{ 'switch_id': '{req_switch}' }}",headers={'Content-Type': 'application/json'},auth=('admin', 'Danut24680')).json()

                for i in range(len(switch_details['result'])):
                    if (switch_details['result'][i]['ip'] == req_switch_ip):
                        switch_user = switch_details['result'][i]['username']
                        switch_password = switch_details['result'][i]['password']

                # Get credentials from the dictionary
                retrieved_user, retrieved_password = get_credentials(req_switch_ip)

                if retrieved_user is None:
                    retrieved_user = switch_user
                    retrieved_password = switch_password
                if (retrieved_user is not None and retrieved_password is not None):
                    # Check if the credentials status is 'failed' and the last attempt was 5 minutes ago
                    if (
                            retrieved_user == switch_user and
                            retrieved_password == switch_password and
                            req_switch_ip in credential_dict and
                            credential_dict[req_switch_ip]["status"] == "failed"):

                        time_since_last_attempt = time() - credential_dict[req_switch_ip]["timestamp"]
                        if time_since_last_attempt > 300:  # 300 seconds = 5 minutes
                            try:
                                if req_cmd != "" and req_port_mode == "":
                                    if req_interface_name != "":
                                        output = run_command_and_get_json(req_switch_ip, retrieved_user, retrieved_password, req_cmd)
                                    else:
                                        output = run_command_and_get_json(req_switch_ip, retrieved_user, retrieved_password, req_cmd)
                                else:
                                    output = change_interface_mode(req_switch_ip, retrieved_user, retrieved_password, req_interface_name, req_port_mode, req_vlans)

                                if glv.added_vlan is not None:  # Check if a VLAN was added
                                    output_message = "Added VLANs: " + ", ".join(map(str, added_vlan))
                                    glv.added_vlan = None  # Reset it after displaying the message
                                else:
                                    output_message = ""

                            except Exception as error:
                                status_message = "status: failed"
                                output = f"{status_message} {error}"
                                send_status_update(req_id, "failed", error)
                                # Update the credentials with a "failed" status if not already present
                                if req_switch_ip not in credential_dict or credential_dict[req_switch_ip]["status"] != "failed":
                                    update_credential_dict(req_switch_ip, retrieved_user, retrieved_password, "failed")

                            else:
                                status_message = "status: success"
                                if output_message is not None:
                                    output = f"{status_message}\n{output_message}\n{output}"
                                else:
                                    output = f"{status_message}\n{output}"
                                redis_set(req_id, "completed", output)
                                task_sts = json.loads(redis_server.get(req_id).decode())["status"]
                                send_status_update(req_id, task_sts, output)
                                update_credential_dict(req_switch_ip, retrieved_user, retrieved_password, "success")

                    else:
                        try:
                            if req_cmd != "" and req_port_mode == "":
                                if req_interface_name != "":
                                    output = run_command_and_get_json(req_switch_ip, retrieved_user, retrieved_password, req_cmd)
                                else:
                                    output = run_command_and_get_json(req_switch_ip, retrieved_user, retrieved_password, req_cmd)
                            else:
                                output = change_interface_mode(req_switch_ip, retrieved_user, retrieved_password, req_interface_name, req_port_mode, req_vlans)

                            if glv.added_vlan is not None:  # Check if a VLAN was added
                                output_message = "Added VLANs: " + ", ".join(map(str, added_vlan))
                                glv.added_vlan = None  # Reset it after displaying the message
                            else:
                                output_message = ""

                        except Exception as error:
                            status_message = "status: failed"
                            output = f"{status_message} {error}"
                            send_status_update(req_id, "failed", error)
                            #Update the credentials with a "failed" status if not already present
                            if req_switch_ip not in credential_dict or credential_dict[req_switch_ip]["status"] != "failed":
                                update_credential_dict(req_switch_ip, retrieved_user, retrieved_password, "failed")

                        else:
                            status_message = "status: success"
                            if output_message is not None:
                                output = f"{status_message}\n{output_message}\n{output}"
                            else:
                                output = f"{status_message}\n{output}"
                            redis_set(req_id, "completed", output)
                            task_sts = json.loads(redis_server.get(req_id).decode())["status"]
                            send_status_update(req_id, task_sts, output)
                            update_credential_dict(req_switch_ip, retrieved_user, retrieved_password, "success")

                print(credential_dict)

            elif "completed" in str(task_sts):
                continue

        sleep(10)

if __name__ == "__main__":
    main()
