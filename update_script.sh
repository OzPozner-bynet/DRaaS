# File to store project directory and venv flag
config_file="config/draas_config.ini"

# Log file path
log_file="/var/log/update_script.log"

# Function to prompt user for project directory
get_project_info() 
{
    project_dir=$(pwd)
    if [[ "$(python3 -V)" =~ "Python 3" ]]; then
		echo "Python 3 is installed" >> "$log_file"
    else
	    echo "Please install python 3" >> "$log_file"
	    exit 1 
    fi

    if [ ! -d $project_dir/venv ]; then
        echo "Setting up virtual environment..." >> "$log_file"
    	python3 -m venv "$project_dir/venv"
    	source "$project_dir/venv/bin/activate"
    else
    	source "$project_dir/venv/bin/activate"
    fi 
    echo "project_dir=$project_dir" > "$config_file"
}

# Function to ask the user about the "whoami" command for the user parameter
ask_user_about_username() {
    read -p "Do you want to use the current user ($(whoami)) as the service username? (yes/no): " use_whoami
    if [ "$use_whoami" == "no" ]; then
        read -p "Enter the desired username: " custom_user
        echo "user=$custom_user" >> "$config_file"
    else
        echo "user=$(whoami)" >> "$config_file"
    fi
}

# Check if the project information is saved, otherwise ask the user
if [ -f "$config_file" ]; then
    source $config_file
else
    get_project_info
fi

# Find the configuration file under the 'config' directory
config_dir="$project_dir/config/"
ini_file="$(find "$config_dir" -maxdepth 1 -type f -iname "*.ini" -print -quit)"

# Check if the parameters.ini file was found
if [ -z "$ini_file" ]; then
    echo "Error: No configuration file (*.ini) found in the 'config' directory. Please check your repository." >> "$log_file"
    exit 1
fi

# Back up the parameters.ini file
backup_dir="/opt/backup"

# Check if the backup directory exists, if not, create it
if [ ! -d "$backup_dir" ]; then
    sudo mkdir -p "$backup_dir"
    sudo chmod a+rw "$backup_dir" -R 
fi
backup_file="$backup_dir/parameters_backup.ini"

# Copy the parameters.ini file to the backup directory
sudo cp "$ini_file" "$backup_file"

# Parse the parameters.ini file to get the values
mid_server=$(awk -F "=" '/^MID_SERVER/ {print $2}' "$ini_file")

# Ensure you are on the main branch
git checkout main

# Discard local changes and reset to the remote main branch
git fetch origin main
git reset --hard origin/main

# Activate virtual environment if it exists
if [ $project_dir/venv ]; then
    source "$project_dir/venv/bin/activate"
else
    # Create and activate virtual environment if it doesn't exist
    python3 -m venv "$project_dir/venv"
    source "$project_dir/venv/bin/activate"
fi

# Install Python dependencies
pip install -r requirements.txt
# Copy the 'config' directory to /opt/
sudo cp -a "$config_dir" /opt/

# Function to update service file with correct parameters
update_service_file() {
    local service_file="$1"
    local user_param="User=$(whoami)"
    local wd_param="WorkingDirectory=$project_dir"
    local exec_param="ExecStart=$project_dir/venv/bin/python $project_dir/$2.py"

    # Check if the service file exists
    if [ ! -f "$service_file" ]; then
        echo "$2 service file not found in the system. Creating..." >> "$log_file"
        sed -i "s/User=.*/$user_param/" "$project_dir/$2.service"
        sed -i "s/WorkingDirectory=.*/$wd_param/" "$project_dir/$2.service"
        sed -i "s|ExecStart=.*|$exec_param|" "$project_dir/$2.service"
        sudo cp "$project_dir/$2.service" "$service_file"
    else
        # Check if parameters match, update if needed
        if ! grep -q "^$user_param" "$service_file" || ! grep -q "^$wd_param" "$service_file" || ! grep -q "^$exec_param" "$service_file"; then
            echo "$2 service file parameters do not match. Updating..." >> "$log_file"
            sudo sed -i "s/User=.*/$user_param/" "$service_file"
            sudo sed -i "s/WorkingDirectory=.*/$wd_param/" "$service_file"
            sudo sed -i "s|ExecStart=.*|$exec_param|" "$service_file"
        fi
    fi
}

# Check if service files exist, otherwise copy them
producer_service="/etc/systemd/system/producer.service"
consumer_service="/etc/systemd/system/consumer.service"
# Check if the config_file contains the user parameter
if grep -q "^user=" "$config_file"; then
    source $config_file
else
    ask_user_about_username
fi

update_service_file "$producer_service" "producer"
update_service_file "$consumer_service" "consumer"

# Reload systemd to pick up changes
sudo systemctl daemon-reload

# Restart your services and log the output
sudo systemctl restart producer.service > "$log_file" 2>&1
sudo systemctl restart consumer.service >> "$log_file" 2>&1

# Check the status of the services
producer_status=$(sudo systemctl is-active producer.service)
consumer_status=$(sudo systemctl is-active consumer.service)

# Deactivate virtual environment
deactivate

# Print the status message
if [ "$producer_status" = "active" ] && [ "$consumer_status" = "active" ]; then
    echo "All services are up." >> "$log_file"
    echo "MID Server: $mid_server" >> "$log_file"
else
    echo "Something went wrong. Check the status of your services. See the log file for details: $log_file"
fi

