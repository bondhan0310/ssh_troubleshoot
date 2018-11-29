ssh_troubleshoot

Created by Bond Han on 2018-10-21

This script applies to Azure Linux VMs that fail to be connected via SSH but the OS is up and supports serial console.

Kindly note that currently this script is designed to focus on below OS versions, other OS versions might not be fully supported yet.

     Redhat 7 or higher
     Ubuntu 16 or higher

How to use:

1. Login the VM in problem via serial console from Azure Portal.
2. Create a file named abc.sh(any name is OK but not "ssh.sh"), then copy the content of network_basic.sh(https://github.com/bondhan0310/ssh_troubleshoot/blob/master/network_basic.sh) and paste it to abc.sh.
3. Save file abc.sh and exit, then run command "chmod 777 abc.sh"
4. Please grant root permission first, then run "./abc.sh" and input the required information when needed.
 
You are welcome to use it and test it! Please feel free to provide feedback to wehan@microsoft.com, we value you the most:)

Function List:

 welcome
 
 initial_

 check_os
 
 check_traffic

 check_pubkey

 check_ssh_host_ecdsa_key_permission

 check_ssh_host_ed25519_key_permission
 
 check_ssh_host_rsa_key_permission
 
 check_ssh_status

 check_ssh_config

 check_var_empty_sshd
 
 check_etc_pamd_sshd
 
 #check_selinux

 check_firewall
 
 check_user_status
 
 check_file_folder_permission

 check_hostdeny
 
 print_report

 suggestion
