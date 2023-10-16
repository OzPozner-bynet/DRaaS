#Need to install requests package for python
import requests

from functions import change_interface_mode
from functions import run_command_and_get_json

# Set the request parameters
url = 'https://bynetdev.service-now.com/api/now/table/x_bdml_draas_switch_info/'
queue_name = "api_req_queue"
snow_url = "https://bynetprod.service-now.com/api/bdml/switch"
switch_info_url = "https://bynetprod.service-now.com/api/bdml/parse_switch_json/SwitchIPs"
get_cmds_url = snow_url+"/getCommands"
update_req_url = snow_url+"/SetCommandStatus"

# Eg. User name="username", Password="password" for this code sample.
switch_user = "shapi"
switch_password = "patish"
req_switch_ip = "172.31.78.200"
req_interface_name = "Gi0/9"

# Set proper headers
#headers = {"Accept":"application/json",'Content-type':'application/json'}
#output = change_interface_mode(req_switch_ip, switch_user, switch_password, req_interface_name, "trunk", "63,64")

#output2 = get_switch_ios(req_switch_ip, switch_user, switch_password)

#output = run_command_on_device_wo_close(req_switch_ip, switch_user , switch_password, "terminal length 0", None)

json_data = run_command_and_get_json(req_switch_ip , switch_user, switch_password, (run_command_on_device_wo_close(req_switch_ip, switch_user, switch_password, "SHOW RUN")))
print(json_data)
# Print the JSON data


#change_interface_mode(ip_address, "shapi", "patish", None, "interface="+interface, "status=disable")