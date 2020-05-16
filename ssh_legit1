#!/bin/bash
#ssh attack to 10.0.4.2 in LegitNet 1

ssh-keygen -f "/root/.ssh/known_hosts" -R "10.0.4.2"
echo "which IP to target for ssh attack?"
read target
echo "What is the username?"
read username
echo "What is the password?"
read -s password
ssh "$username@$target"
