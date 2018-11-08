ssh_troubleshoot
Created by Bond Han on 2018-10-21
This script applies to Azure Linux VMs that fail to be connected via SSH but the OS is up and supports serial console.
Kindly note that currently this script is designed to focus on below OS versions, other OS versions might not be fully supported yet.

     Redhat 7 or higher
     Ubuntu 16 or higher

How to use:

1. Login the VM in problem via serial console from Azure Portal.
2. Create a file named abc.sh(for example), then copy the content of network_basic.sh(https://raw.githubusercontent.com/bondhan0310/ssh_troubleshoot/master/network_basic.sh) and paste it to abc.sh.
3. Save file abc.sh and exit, then run command "chmod 777 abc.sh"
4. Please grant root permission first, then run "./abc.sh" and input the required information when needed.
 
You are welcome to use it and test it! Please feel free to provide feedback to wehan@microsoft.com, we value you the most:)
