import os
import paramiko
import yaml
from wrapper import *
from datetime import datetime
boxes = {}
config_path = 'config.yml'
with open(config_path, 'r') as file:
        data = yaml.safe_load(file)

def Root_Password_Changes(ssh, box):
    root_password = boxes[box][1]
    command = f'passwd root {root_password}'
    run_ssh_command(command,box)

def User_Password_Changes(ssh, box):
    user_password = boxes[box][2]
    command = f'for u in $(cat /etc/passwd | grep -v ^root: | cut -d: -f1); do echo "$u:{user_password}" | chpasswd; done'
    run_ssh_command(command,box)


def files_to_backup(ssh, box):
    files_to_backup_entry = data.get('files_to_backup', [])
    for file in files_to_backup_entry:
        command = f'cp {file} /root/{file}'
        run_ssh_command(command,box)


def firewall_stuff(ssh, ports, box):
    # Implement this here
    command = "Your Firewall Command Here"
    run_ssh_command(command,box)

def audit_Users(ssh, box):
    command = "grep -E '/bash$|/sh$' /etc/passwd"
    stdout = run_ssh_command(command,box,False)
    users_data = stdout.read().decode('utf-8').strip()
    section_header = f"=== {box} ==="
    data_to_write = f"{section_header}\n{users_data}\n\n"
    with open('Audited_Users.txt', 'a') as file:
        file.write(data_to_write)



def change_SSH_Settings(ssh,box):
    #Maybe move to yml undecided atm
    ssh_commands = [
    "sed -i '1s;^;PermitRootLogin yes\n;' /etc/ssh/sshd_config",
    "sed -i '1s;^;PubkeyAuthentication no\n;' /etc/ssh/sshd_config",
    "sed -i '1s;^;UseDNS no\n;' /etc/ssh/sshd_config",
	"sed -i '1s;^;PermitEmptyPasswords no\n;' /etc/ssh/sshd_config",
	"sed -i '1s;^;AddressFamily inet\n;' /etc/ssh/sshd_config"
    # Add more commands as needed
]
    
    for command in ssh_commands:
        run_ssh_command(command,box)


def modify_php_settings(ssh, php_config_path, settings, box):
    php_settings_entry = data.get('php_settings', {})
    for setting, value in php_settings_entry.items():
        command = f"echo '{setting} = {value}' >> {php_config_path}"
        run_ssh_command(command,box)

def change_sysctl_settings(ssh,box):
    sysctl_settings_entry = data.get('sysctl_settings', {})
    for setting, value in sysctl_settings_entry.items():
        command = f"echo '{setting} = {value}' >> /etc/sysctl.d/99-sysctl.conf"
        run_ssh_command(command,box)
        command="sysctl -p"
        run_ssh_command(command,box)



def run_single_command(ssh,box,cmd):
    run_ssh_command(cmd,box)

def execute_BashScript(ssh, script, box):
    try:
        with open(script, 'r') as bash_script:
            # Read the entire script into a string
            script_content = bash_script.read()

            # Execute the entire script
            _, stdout, _ = ssh.exec_command(script_content)
            result = stdout.read().decode('utf-8').strip()

            # Log the command execution
            log_command_execution(script_content, result, box)

    except Exception as e:
        print(f"Error: {e}")
def enumerate(ssh,box):
    #Likely we just want to use the cpp enumeration script
    print("enum")

def fix_pam(ssh,box):
    #Possible SCP from a local baseline to server
    print("pam")

def generate_PCR(ssh,box):
    #Either take it from audited user or run another audit user command?
    print("pcr")



functions = [Root_Password_Changes,User_Password_Changes,files_to_backup,firewall_stuff,audit_Users,execute_BashScript,change_SSH_Settings,modify_php_settings,run_single_command,change_sysctl_settings]
def exec_function(function_number,arg1,arg2,arg3):
     for line in open("boxes.conf"):
        if "#" not in line:
            components = line.strip().split(',')
            ip_address = components[0]
            default_password = components[1]
            root_password = components[2]
            user_password = components[3]
            boxes[ip_address]=(default_password,root_password,user_password)

            # Create base SSH config
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip_address, username='root', password=default_password)
            # Perform the action
            #file.write(f"\n=== {ip_address} ===\n")
            functions[function_number](ssh,ip_address)
            ssh.close()



def main():
    # Read the YAML data from a file
    config_path = 'config.yml'
    with open(config_path, 'r') as file:
        data = yaml.safe_load(file)

    # Display menu options
    print("\nSelect an option:")
    print("1. Audit Users")
    print("2. Root Password Changes")
    print("3. User Password Changes")
    print("4. Files Backup")
    print("5. Firewall Stuff")
    print("6. Execute Bash Script")
    print("7. Change SSH Settings")
    print("8. Modify PHP Settings")
    print("9. Change Sysctl Settings")
    print("10. Run Single Command")
    print("0. Exit")
    option = input("Enter the option number: ")
    if(int(option) >= 0 and int(option) <= 10):
        exec_function(option)
