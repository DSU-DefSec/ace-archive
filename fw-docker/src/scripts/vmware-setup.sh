#!/usr/bin/env bash 
read -p "ESXi Host IP: " esxi_host_ip
read -p "ESXi Host Password: " esxi_host_pw
read -p "Firewall Name: " fw_name



# ssh-keygen -t rsa -b 4096 -C "ansible@localhost" -f ~/.ssh/id_rsa -N ""


#Line below came from chatgpt
api_key=$(curl -s -k -H "Content-Type: application/x-www-form-urlencoded" -X POST "https://${palo_ip}/api/?type=keygen" -d "user=admin&password=${palo_pw}" | grep -oP '(?<=<key>)[^<]+')

# Output to fw.yml 
cat >> data/inv.yml <<EOF
esxi:
  hosts:
    ${esxi_host_ip}:
      esxi_user: root
      esxi_password: ${esxi_host_pw}
      fw_name: ${fw_name}

EOF

cat ~/data/inv.yml

# sudo ansible-vault encrypt inv.yml