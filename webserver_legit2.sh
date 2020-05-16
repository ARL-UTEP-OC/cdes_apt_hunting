#!/bin/bash
#sqlinjection attack in 10.0.14.100  in LegitNet 2 using Metasploit and proxychain to use SQLMap

echo "which IP to target for ssh attack?"
read target
echo "What is the username?"
read username
echo "What is the password?"
read -s password
msfconsole
