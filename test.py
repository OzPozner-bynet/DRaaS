#Need to install requests package for python
import requests
import json
from functions import change_interface_mode
from functions import run_command_and_get_json
import re

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
req_switch_ip = "172.31.78.150"
req_interface_name = "Gi0/10"
req_interface_name2 = "Gi0/12"
# Set proper headers
#headers = {"Accept":"application/json",'Content-type':'application/json'}
#output = change_interface_mode(req_switch_ip, switch_user, switch_password, req_interface_name, "trunk", "63,64")

#output2 = get_switch_ios(req_switch_ip, switch_user, switch_password)

#output = run_command_on_device_wo_close(req_switch_ip, switch_user , switch_password, "terminal length 0", None)

info_before = run_command_and_get_json(req_switch_ip, switch_user, switch_password, f"show interface {req_interface_name}")
info_after = run_command_and_get_json(req_switch_ip, switch_user, switch_password, f"show interface {req_interface_name2}")

print(info_after)
print(info_before)

def find_added_vlans(info_before, info_after):
    # Split the "show vlan" output into VLAN entries
    vlan_entries_before = re.findall(r"(\d+)\s+(\S+)\s+active\s+(.+)", info_before)
    vlan_entries_after = re.findall(r"(\d+)\s+(\S+)\s+active\s+(.+)", info_after)

    # Create sets of VLAN IDs for both before and after
    vlan_ids_before = set(entry[0] for entry in vlan_entries_before)
    vlan_ids_after = set(entry[0] for entry in vlan_entries_after)

    # Identify added VLANs
    added_vlans = vlan_ids_after - vlan_ids_before

    # Return the added VLAN IDs as a list
    return list(added_vlans)


print( (find_added_vlans(info_before, info_after)))