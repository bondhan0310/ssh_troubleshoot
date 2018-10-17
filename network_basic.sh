#!/bin/bash

        current_dir=$(pwd)
        if [ -e /etc/os-release ]; then

                os_detail=$(cat /etc/os-release | grep PRETTY | awk -F '"' '{print $2}')
                os_tran=$(echo $os_detail | sed s/[[:space:]]//g)
                if [ "$os_detail"=~"Red" -o "$os_tran"=~"Cent" ]; then

                        os_flag=r

                elif [ "$os_detail"=~"buntu" -o "$os_detail" =~ "ebian" ]; then

                        os_flag=u

                else

                        echo "OS is not supported, scripts will be terminated!"

                fi

        else

                echo "OS is not supported, scripts will be terminated!"

        fi
        layer2_status=$(arp -a)
        if [ "$layer2_status"=~"12:34:56:78:9a:bc" ]; then

                echo "Layer2 network is good~"

        else

                echo "Problem detected in layer2 network!"

        fi
        if [ $os_flag == "r" ]; then

                vm_ip=$(ifconfig eth0 | sed -n '2p' | awk '{print $2}')

        else

                vm_ip=$(ifconfig eth0 | sed -n '2p' | awk '{print $2}' | awk -F':' '{print $2}')

        fi
        echo "VM private IP is: $vm_ip"
        gateway_1=$(echo $vm_ip | awk -F'.' '{print $1}')
        gateway_2=$(echo $vm_ip | awk -F'.' '{print $2}')
        gateway_3=$(echo $vm_ip | awk -F'.' '{print $3}')
        sp="."
        ad="0"
        destination=$gateway_1$sp$gateway_2$sp$gateway_3$sp$ad
        layer3_status=$(route | grep $destination)
        if [ -z "$layer3_status" ]; then

                echo "Problem detected in layer3 newtork!"

        else

                echo "Layer3 network is good~"
		wget https://github.com/bondhan0310/ssh_troubleshoot/blob/master/ssh_ts.sh
		sleep 5

        fi


	if [ ! -f "$current_dir/ssh_ts.sh" ];then

		echo "wget failed!"
	else

		chmod 777 $current_dir/ssh_ts.sh
		echo "Please consider running the SSH troubleshooting scripts"

	fi


