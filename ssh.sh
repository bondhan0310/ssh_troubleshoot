#!/bin/bash
function welcome(){

	echo ""
	echo ""
	echo "######################################################################"
	echo "######################################################################"
	echo " Welcome to Microsoft Azure SSH failure Troubleshooting Master Demo!"
	echo "######################################################################"
	echo "######################################################################"
	echo ""

}
function initial_(){

	echo ""
	echo "#######################################"
	echo " Now initializing the troubleshooting~"
	echo "#######################################"
	echo ""

	read -p "Please input the username that fails SSH: " username
	read -p "Please input IP address(When target IP is public IP, please input the client's public IP) of the client that fails SSH: " client_ip
	ssh_port=""
	vm_ip=""
	current_dir=$(pwd)

}

function check_os(){

	
	echo ""
	echo "######################"
	echo " Now checking the OS~"
	echo "######################"
	echo ""

	if [ -e /etc/os-release ]; then	

		os_detail=$(cat /etc/os-release | grep PRETTY | awk -F '"' '{print $2}')
		os_tran=$(echo $os_detail | sed s/[[:space:]]//g)
		if [[ "$os_detail" =~ "Red" ]] || [[ "$os_tran" =~ "Cent" ]]; then
	
			os_flag=r

		elif [[ "$os_detail" =~ "buntu" ]] || [[ "$os_detail" =~ "ebian" ]]; then

			os_flag=u

		else

			echo "OS is not supported, scripts will be terminated!"

		fi

	else 

		echo "OS is not supported, scripts will be terminated!"
		exit 0

	fi
	
	echo "OS version is: $os_detail"
	echo "++++    OS version is: $os_detail" >> $current_dir/report.txt

}
check_pubkey(){

	ecdsa=$(ls -l /etc/ssh | grep ssh_host_ecdsa_key.pub)
	ednumber=$(ls -l /etc/ssh | grep ssh_host_ed25519_key.pub)
	rsa=$(ls -l /etc/ssh | grep ssh_host_rsa_key.pub)

	if [ -z "$ecdsa" ]; then

		echo "ssh_host_ecdsa_key.pub under /etc/ssh is missing!"
		echo "++++    ssh_host_ecdsa_key.pub under /etc/ssh is missing!" >> $current_dir/report.txt
                echo "++++    Ecdsa_key checking --- Failed --- Please make sure file /etc/ssh/ssh_host_ecdsa_key.pub exists!" >> $current_dir/suggestion.txt

	else 

		echo "ecdsa_key.pub checking pass~"

	fi


	if [ -z "$ednumber" ]; then

		echo "ssh_host_ed25519_key.pub under /etc/ssh is missing!"
		echo "++++    ssh_host_ed25519_key.pub under /etc/ssh is missing!" >> $current_dir/report.txt
                echo "++++    Ed25519_key checking --- Failed --- Please make sure file /etc/ssh/ssh_host_ed25519__key.pub exists!" >> $current_dir/suggestion.txt

	else 

		echo "ed25519_key.pub checking pass~"

	fi

	if [ -z "$rsa" ]; then

		echo "ssh_host_rsa_key.pub under /etc/ssh is missing!"
		echo "++++    ssh_host_rsa_key.pub under /etc/ssh is missing!" >> $current_dir/report.txt
                echo "++++    RSA_key checking --- Failed --- Please make sure file /etc/ssh/ssh_host_rsa__key.pub exists!" >> $current_dir/suggestion.txt

	else 

		echo "rsa_key.pub checking pass~"

	fi

}

function check_traffic(){

		
	echo ""
	echo "###########################"
	echo " Now checking the network~"
	echo "###########################"
	echo ""

	if [ $os_flag == "r" ]; then

		vm_ip=$(ifconfig eth0 | sed -n '2p' | awk '{print $2}')

	else 

		vm_ip=$(ifconfig eth0 | sed -n '2p' | awk '{print $2}' | awk -F':' '{print $2}') 

	fi

	echo "VM private IP is: $vm_ip"
	echo "++++    VM private IP is: $vm_ip" >> $current_dir/report.txt
	
	target_ip="168.63.129.16"
	
        echo "Client IP is $client_ip"

        {
                tcpdump -i eth0 src $client_ip > test_tcpdump.txt
        }&

        sleep 3

        if [ -n "$(ps -ef | grep tcpdump)" ]; then

                echo "Tcpdump is running~"

        else

        echo "Tcpdump is not running!"

        fi

        tcpdump_pid=$(ps -ef | grep $client_ip | sed -n '1p' | awk '{print $2}')

        sleep 5
        kill -15 $tcpdump_pid
        wait

        if [ `grep -c "ack" $current_dir/test_tcpdump.txt` -eq '0' ]; then

                echo "No packets received from client IP: $client_ip ~"
                echo "++++    No packets received from client IP: $client_ip ~" >> $current_dir/report.txt

        else

                echo "Packets received from client IP: $client_ip ~"
                echo "++++    Network is good!" >> $current_dir/report.txt

        fi

        rm -rf $current_dir/test_tcpdump.txt
}


function check_firewall(){

        echo ""
        echo "###########################"
        echo " Now checking the Firewall~"
        echo "###########################"
        echo ""

        if [ $os_flag == "r" ]; then

                firewall_status=$(systemctl status firewalld.service | sed -n '3p' | awk '{print $3}')

                        if [[ "$firewall_status" =~ "running" ]]; then


                                echo "Firewall is running!"

				if [[ $ssh_running_port == "22" ]]; then
                                firewall_port_status_reject=$(iptables -L | grep $ssh_running_port | grep REJECT)
                                firewall_port_status_drop=$(iptables -L | grep $ssh_running_port | grep DROP)
                                firewall_ip_status_reject=$(iptables -L | grep $client_ip | grep REJECT | grep $ssh_running_port)
                                firewall_ip_status_drop=$(iptables -L | grep $client_ip | grep DROP | grep $ssh_running_port)
				firewall_ssh_status_reject=$(iptables -L | grep ssh | grep REJECT)
				firewall_ssh_status_drop=$(iptables -L | grep ssh | grep DROP)
                                if [[ -z "$firewall_port_status_reject" ]] && [[ -z "$firewall_port_status_drop" ]] ; then

                                        echo "SSH running port $ssh_running_port is allowed by Firewall~"
                                        echo "++++    SSH running port $ssh_running_port is allowed by Firewall~" >> $current_dir/report.txt

                                else

                                        echo "SSH running port $ssh_running_port is not allowed by Firewall!"
                                        echo "++++    SSH running port $ssh_running_port is not allowed by Firewall!" >> $current_dir/report.txt
                                        echo "++++    Port allowed checking --- Failed --- Please make sure Port $ssh_running_port is allowed by Firewall(iptables -L)" >> $current_dir/suggestion.txt

                                fi

                                if [[ -z "$firewall_ip_status_reject" ]] && [[ -z "$firewall_ip_status_drop" ]]; then

                                        echo "Client IP $client_ip is allowed by Firewall~"
                                        echo "++++    Client IP $client_ip is allowed by Firewall~" >> $current_dir/report.txt

                                else


                                        echo "Client IP $client_ip is not allowed by Firewall!"
                                        echo "++++    Client IP $client_ip is not allowed by Firewall!" >> $current_dir/report.txt
                                        echo "++++    Client IP allowed checking --- Failed --- Please make sure Client IP: $client_ip is allowed by Firewall(iptables -L)" >> $current_dir/suggestion.txt
				fi	
                                if [[ -z "$firewall_ssh_status_reject" ]] && [[ -z "$firewall_ssh_status_drop" ]]; then

                                        echo "SSH service is allowed by Firewall~"
                                        echo "++++    SSH service is allowed by Firewall~" >> $current_dir/report.txt
								
								elif [[ "$firewall_ssh_status_reject" =~ "$client_ip" ]] || [[ "$firewall_ssh_status_drop" =~ "$client_ip" ]]; then
								
										echo "Client IP $client_ip is not allowed to use SSH by Firewall!"
                                        echo "++++    Client IP $client_ip is not allowed to use SSH service by Firewall!" >> $current_dir/report.txt
                                        echo "++++    SSH service allowed checking --- Failed --- Please make sure Client IP $client_ip is allowed to use SSH service by Firewall(remove related rule iptables)" >> $current_dir/suggestion.txt
								
								elif [[ "$firewall_ssh_status_reject" =~ "." ]] || [[ "$firewall_ssh_status_drop" =~ "." ]]; then
								
										echo "Some specific client IPs might not be allowed to use SSH service by Firewall!"
										echo "++++    Some specific client IPs might not be allowed to use SSH service by Firewall!" >> $current_dir/report.txt
								
                                else


                                        echo "SSH service is not allowed by Firewall!"
                                        echo "++++    SSH service is not allowed by Firewall!" >> $current_dir/report.txt
                                        echo "++++    SSH service allowed checking --- Failed --- Please make sure SSH service is allowed by Firewall(remove related rule iptables)" >> $current_dir/suggestion.txt
                                fi
				else
				check_customized_sshport_r
				fi

				

                        else

                                echo "Firewall is not running~"
                                echo "++++    Firewall is not running~" >> $current_dir/report.txt

                        fi

        else

                firewall_status=$(ufw status)

                        if [[ "$firewall_status" =~ "inactive" ]]; then

                                echo "Firewall is not running~"
                                echo "++++    Firewall is not running~" >> $current_dir/report.txt

                        else
                                echo "Firewall is running!"
                                echo "++++    Firewall is running!" >> $current_dir/report.txt
                                if [[ $ssh_running_port == "22" ]]; then
					ufw_port_status=$(ufw status | grep 22\/tcp | grep ALLOW)
					ufw_clientip_status=$(ufw status | grep $client_ip | grep 22)
					ufw_clientip_status2=$(ufw status | grep $client_ip | grep Anywhere)
					if [[ -z "$ufw_port_status" ]]; then

				        	echo "Port 22 is denied in UFW configuration"
                                		echo "++++    Port 22 is denied in UFW configuration" >> $current_dir/report.txt
                                		echo "++++    Port 22 allowed checking --- Failed --- Please make sure Port 22 is allowed in UFW(ufw allow $ssh_running_port) " >> $current_dir/suggestion.txt

					else

				        	echo "Port 22 is allowed in UFW configuration"
                                		echo "++++    Port 22 is allowed in UFW configuration" >> $current_dir/report.txt

					fi
					if [[ "$ufw_clientip_status" =~ "DENY" ]] || [[ "$ufw_clientip_status2" =~ "DENY" ]]; then

				        	echo "Client IP $client_ip is not allowed to access Port $ssh_running_port in UFW configuration"
                                		echo "++++    Client IP $client_ip is not allowed to access Port $ssh_running_port in UFW configuration" >> $current_dir/report.txt
                                		echo "++++     Client IP $client_id allowed checking --- Failed --- Please make sure Client IP $client_ip is allowed to access Port $ssh_running_port is allowed in UFW(ufw allow $client_ip) " >> $current_dir/suggestion.txt

					else

				        	echo "Client IP $client_ip is allowed in UFW configuration"
                                		echo "++++    Client IP $client_ip is allowed in UFW configuration" >> $current_dir/report.txt

					fi




				else

                                        ufw_port_status=$(ufw status | grep $ssh_running_port | grep ALLOW)
                                        ufw_clientip_status=$(ufw status | grep $client_ip | grep $ssh_running_port)
                                        ufw_clientip_status2=$(ufw status | grep $client_ip | grep Anywhere)
                                        if [[ -z "$ufw_port_status" ]]; then

                                                echo "SSH Running Port $ssh_running_port is denied in UFW configuration"
                                                echo "++++    SSH running Port $ssh_running_port is denied in UFW configuration" >> $current_dir/report.txt
                                                echo "++++    SSH running Port $ssh_running_port allowed checking --- Failed --- Please make sure Port $ssh_running_port is allowed in UFW(ufw allow $ssh_running_port) " >> $current_dir/suggestion.txt

                                        else

                                                echo "SSH Running Port $ssh_running_port is allowed in UFW configuration"
                                                echo "++++    SSH Running Port $ssh_running_port is allowed in UFW configuration" >> $current_dir/report.txt

                                        fi
                                        if [[ "$ufw_clientip_status" =~ "DENY" ]] || [[ "$ufw_clientip_status2" =~ "DENY" ]]; then

                                                echo "Client IP $client_ip is not allowed to access Port $ssh_running_port in UFW configuration"
                                                echo "++++    Client IP $client_ip is not allowed to access Port $ssh_running_port in UFW configuration" >> $current_dir/report.txt
                                                echo "++++     Client IP $client_id allowed checking --- Failed --- Please make sure Client IP $client_ip is allowed to access Port $ssh_running_port is allowed in UFW(ufw allow $client_ip) " >> $current_dir/suggestion.txt

                                        else

                                                echo "Clinet IP $client_ip is allowed in UFW configuration"
                                                echo "++++    Client IP $client_ip is allowed in UFW configuration" >> $current_dir/report.txt

                                        fi



				


				fi





                fi

        fi

}

function check_ssh_status(){


        echo ""
        echo "#####################################"
        echo "Now checking the SSH service status~"
        echo "#####################################"
        echo ""

        ssh_status=$(systemctl status sshd.service | sed -n '3p' | awk '{print $3}' )

                if [[ "$ssh_status" =~ "running" ]]; then

                        echo "SSH is running~"
                        echo "++++    SSH is running~" >> $current_dir/report.txt

                else

                        echo "SSH is not running!"
                        echo "++++    SSH is not running!" >> $current_dir/report.txt
                        echo "++++    SSH running status checking --- Failed --- Please make sure SSH service is running(_service sshd start/systemctl start sshd.service)" >> $current_dir/suggestion.txt

                fi

}

function check_ssh_config(){

        echo ""
        echo "####################################"
        echo "Now checking the SSH configuration~"
        echo "####################################"
        echo ""

        ssh_port_check=$(cat /etc/ssh/sshd_config | grep Port | sed -e '/#/d' | awk '{print $2}')
		space_check=$(cat /etc/ssh/sshd_config | grep Port | sed -e '/#/d' | awk '{print $3}')
		space=" "

	echo $ssh_port_check
        if [ -z "$ssh_port_check" ]; then

                ssh_port="22"

		elif [ -n "$space_check" ]; then

				ssh_port=$ssh_port_check$space$space_check

        else

                ssh_port=$ssh_port_check

        fi

        echo "SSH config port is: $ssh_port"
        echo "++++    SSH config port is: $ssh_port" >> $current_dir/report.txt
		
		if [ -n "$space_check" ]; then

			space_flag="f"
			echo "++++    Space detected in SSH port number, which might be the reason why sshd service fails to be started!" >> $current_dir/report.txt
			echo "++++    SSH port validation --- Failed --- Please remove the space from defined SSH port number $ssh_port and then check if it is a proper int value between 1 and 65535" >> $current_dir/suggestion.txt
		
		
		elif [[ "$ssh_port" =~ "." ]] || [[ "$ssh_port" -gt "65535" ]]; then
		
			port_flag="f"
			echo "++++    SSH config port is: $ssh_port, which is invalid and might be the reason why sshd service fails to be started!" >> $current_dir/report.txt
			echo "++++    SSH port validation --- Failed --- Please change the port number from $ssh_port to a proper int value between 1 and 65535" >> $current_dir/suggestion.txt


		fi

		if [ -z "$space_check" ]; then

			if grep '^[[:digit:]]*$' <<< "$ssh_port";then

				echo "++++    Defined SSH Port $ssh_port is a pure number~" >> $current_dir/report.txt

			else

				number_flag="f"
				echo "++++    Defined SSH Port $ssh_port contains letter(s) or special character(s), which might be the reason why SSH service fails to be started" >> $current_dir/report.txt
				echo "++++    SSH port validation --- Failed --- Please remove all letter(s) and special character(s) from defined SSH Port number $ssh_port and then check if it is a proper int value between 1 and 65535" >> $current_dir/suggestion.txt

			fi

		fi		

	ssh_running_port=$(netstat -tulpn | grep ssh | sed -e '/tcp6/d' | awk '{print $4}' |  awk -F':' '{print $2}')

	if [[ -z "$ssh_running_port" ]]; then

		ssh_running_port=$ssh_port
	fi

        echo "SSH running port is: $ssh_running_port"
        echo "++++    SSH running port is: $ssh_running_port" >> $current_dir/report.txt

        PasswordAuthentication=$(cat /etc/ssh/sshd_config | grep PasswordAuthentication | sed -e '/#/d')
        if [ -z "$PasswordAuthentication" ] || [[ "$PasswordAuthentication" =~ "yes" ]]; then

                echo "PasswordAuthentication is enabled~"
                echo "++++    PasswordAuthentication is enabled~" >> $current_dir/report.txt

        else

                echo "PasswordAuthentication is disabled!"
                echo "++++    PasswordAuthentication is disabled!" >> $current_dir/report.txt
                echo "++++    PasswordAuthentication enabled checking --- Failed --- Please make sure PasswordAuthentication is enabled(/etc/ssh/sshd_config)" >> $current_dir/suggestion.txt
        fi

        PubkeyAuthentication=$(cat /etc/ssh/sshd_config | grep PubkeyAuthentication | sed -e '/#/d')
        if [ -z "$PubkeyAuthentication" ] || [[ "$PubkeyAuthentication" =~ "yes" ]]; then

                echo "PubkeyAuthentication is enabled~"
                echo "++++    PubkeyAuthentication is enabled~" >> $current_dir/report.txt

        else

                echo "PubkeyAuthentication is disabled!"
                echo "++++    PubkeyAuthentication is disabled!" >> $current_dir/report.txt
                echo "++++    PubkeyAuthentication enabled checking --- Failed --- Please make sure PubkeyAuthentication is enabled(/etc/ssh/sshd_config)" >> $current_dir/suggestion.txt

        fi

}

function check_customized_sshport_r(){

        echo ""
        echo "############################################################"
        echo "Now checking if customized SSH port is allowed by Firewall~"
        echo "############################################################"
        echo ""

	if [ "$ssh_running_port" != "22" ] && [ "$port_flag" != "f" ] && [ -z "$space_check" ] && [ "$number_flag" != "f" ]; then

		custom_port=$(iptables -L | grep $ssh_running_port | grep ACCEPT | sed -e '/#/d')
		real_port_allow=$(iptables -L | grep $ssh_running_port | grep ACCEPT | sed -e '/#/d' | awk '{print $7}' | awk -F":" '{print $2}')
		custom_port_reject=$(iptables -L | grep $ssh_running_port | grep REJECT | sed -e '/#/d')
		custom_port_drop=$(iptables -L | grep $ssh_running_port | grep DROP | sed -e '/#/d')
                                firewall_ip_status_reject=$(iptables -L | grep $client_ip | grep REJECT | grep $ssh_running_port)
                                firewall_ip_status_drop=$(iptables -L | grep $client_ip | grep DROP | grep $ssh_running_port)
                                firewall_ssh_status_reject=$(iptables -L | grep ssh | grep REJECT)
                                firewall_ssh_status_drop=$(iptables -L | grep ssh | grep DROP)

		
			if [[ -z "$custom_port" ]] || [[ -n "$custom_port_reject" ]] || [[ -n "$custom_port_reject" ]]; then

			

                		echo "Customized SSH port $ssh_running_port is not allowed by firewall!"
		                echo "++++    Customized SSH port $ssh_running_port is not allowed by firewall!" >> $current_dir/report.txt
                		echo "++++    Customized SSH port checking --- Failed --- Please consider using command firewall-cmd --permanent --add-port=$ssh_running_port/tcp" >> $current_dir/suggestion.txt



			elif [[ "$ssh_running_port" != "$real_port_allow" ]]; then

                		echo "Customized SSH port $ssh_running_port is not allowed by firewall!"
		                echo "++++    Customized SSH port $ssh_running_port is not allowed by firewall!" >> $current_dir/report.txt
                		echo "++++    Customized SSH port checking --- Failed --- Please consider using command firewall-cmd --permanent --add-port=$ssh_running_port/tcp" >> $current_dir/suggestion.txt

			else

		                echo "Customized SSH port $ssh_running_port is allowed by firewall~"
                		echo "++++    Customized SSH port $ssh_running_port is allowed by firewall~" >> $current_dir/report.txt

			fi
                                if [[ -z "$firewall_ip_status_reject" ]] && [[ -z "$firewall_ip_status_drop" ]]; then

                                        echo "Client IP $client_ip is allowed by Firewall~"
                                        echo "++++    Client IP $client_ip is allowed by Firewall~" >> $current_dir/report.txt

                                else


                                        echo "Client IP $client_ip is not allowed by Firewall!"
                                        echo "++++    Client IP $client_ip is not allowed by Firewall!" >> $current_dir/report.txt
                                        echo "++++    Client IP allowed checking --- Failed --- Please make sure Client IP: $client_ip is allowed by Firewall(iptables -L)" >> $current_dir/suggession.txt
                                fi
                                if [[ -z "$firewall_ssh_status_reject" ]] && [[ -z "$firewall_ssh_status_drop" ]]; then

                                        echo "SSH service is allowed by Firewall~"
                                        echo "++++    SSH service is allowed by Firewall~" >> $current_dir/report.txt
																		
								elif [[ "$firewall_ssh_status_reject" =~ "$client_ip" ]] || [[ "$firewall_ssh_status_drop" =~ "$client_ip" ]]; then
								
										echo "Client IP $client_ip is not allowed to use SSH by Firewall!"
                                        echo "++++    Client IP $client_ip is not allowed to use SSH service by Firewall!" >> $current_dir/report.txt
                                        echo "++++    SSH service allowed checking --- Failed --- Please make sure Client IP $client_ip is allowed to use SSH service by Firewall(remove related rule iptables)" >> $current_dir/suggestion.txt
								
								elif [[ "$firewall_ssh_status_reject" =~ "." ]] || [[ "$firewall_ssh_status_drop" =~ "." ]]; then
								
										echo "Some specific client IPs might not be allowed to use SSH service by Firewall!"
										echo "++++    Some specific client IPs might not be allowed to use SSH service by Firewall!" >> $current_dir/report.txt
								
                                else


                                        echo "SSH service is not allowed by Firewall!"
                                        echo "++++    SSH service is not allowed by Firewall from current configuration, double check on iptables is necessary!" >> $current_dir/report.txt
                                fi

				

	else

		echo "There is no customized SSH port~"

	fi

}

function check_user_status(){

        echo ""
        echo "############################################"
        echo "Now checking the username $username status~"
        echo "############################################"
        echo ""

        allow_users=$(cat /etc/ssh/sshd_config | grep AllowUsers | sed -e '/#/d')
        deny_users=$(cat /etc/ssh/sshd_config | grep DenyUsers | sed -e '/#/d')
	deny_allow=a

	if [ -n "$allow_users" ] && [[ "$allow_users" != "$username" ]]; then

		deny_allow=d

	fi
	if [ -z "$allow_users" ] && [[ "$deny_users" =~ "$username" ]]; then

		deny_allow=d

	fi

	if [ "$deny_allow" == d ]; then

                echo "Username $username is denied by SSH!"
                echo "++++    Username $username is denied by SSH!" >> $current_dir/report.txt
                echo "++++    Username allowed checking --- Failed --- Please make sure Username $username is allowed by SSH by editing /etc/ssh/sshd_config" >> $current_dir/suggestion.txt
	else

                echo "Username $username is allowed by SSH!"
                echo "++++    Username $username is allowed by SSH!" >> $current_dir/report.txt

	fi
		
		
}

function check_file_folder_permission(){


        echo ""
        echo "####################################################"
        echo "Now checking the folder /home/$username permission~"
        echo "####################################################"
        echo ""


        permission_output=$(ls -l /home/ | grep $username)
        folder_g=$(echo $permission_output | awk '{print $3}')
        folder_u=$(echo $permission_output | awk '{print $4}')
        folder_p=$(echo $permission_output | awk '{print $1}')

        p1=$(echo $folder_p | awk '{print substr($1,2,1)}')
        p2=$(echo $folder_p | awk '{print substr($1,3,1)}')
        p3=$(echo $folder_p | awk '{print substr($1,4,1)}')

        p4=$(echo $folder_p | awk '{print substr($1,5,1)}')
        p5=$(echo $folder_p | awk '{print substr($1,6,1)}')
        p6=$(echo $folder_p | awk '{print substr($1,7,1)}')

        p7=$(echo $folder_p | awk '{print substr($1,8,1)}')
        p8=$(echo $folder_p | awk '{print substr($1,9,1)}')
        p9=$(echo $folder_p | awk '{print substr($1,10,1)}')

        A=($p1 $p2 $p3 $p4 $p5 $p6 $p7 $p8 $p9)
        len_p=${#A[*]}

        for((i=0;i<$len_p;i++))

        do

                if [ ${A[$i]} == "r" ]; then

                        A[$i]=4

                elif [ ${A[$i]} == "w" ]; then

                        A[$i]=2

                elif [ ${A[$i]} == "x" ]; then

                        A[$i]=1

                else

                        A[$i]=0

                fi

        done

        userselfsum=$((${A[0]}+${A[1]}+${A[2]}))
        usersamegroupsum=$((${A[3]}+${A[4]}+${A[5]}))
        userothergroupsum=$((${A[6]}+${A[7]}+${A[8]}))

        permission_username=${userselfsum}${usersamegroupsum}${userothergroupsum}

	echo "The Permisson of folder /home/$username is $permission_username"
        echo "++++    The Permisson of folder /home/$username is $permission_username" >> $current_dir/report.txt
        echo "The Group of folder /home/$username is $folder_g"
        echo "++++    The Group of folder /home/$username is $folder_g" >> $current_dir/report.txt
        echo "The Owner of folder /home/$username is $folder_u"
        echo "++++    The Owner of folder /home/$username is $folder_u" >> $current_dir/report.txt

        if [ "$os_flag" == "r" ] && [ $permission_username != "700" ]; then

                echo "++++    Folder /home/$username permission checking --- Failed --- Please make sure the perssion is 700!" >> $current_dir/suggestion.txt

        elif [ "$os_flag" == "u" ] && [ $permission_username != "755" ]; then

                echo "++++    Folder /home/$username permission checking --- Failed --- Please make sure the perssion is 755!" >> $current_dir/suggestion.txt

        else

                echo "Permision of folder /home/$username is good ~"

        fi

}

function check_hostdeny(){


        echo ""
        echo "##########################################################"
        echo "Now checking if client IP: $client_ip was denied by host~"
        echo "##########################################################"
        echo ""

        hostdeny_status=$(cat /etc/hosts.deny | grep $client_ip)

        if [ -n "$hostdeny_status" ]; then

                echo "Client IP: $client_ip is denied by this VM!"
                echo "++++    Client IP: $client_ip is denied by this VM!" >> $current_dir/report.txt
                echo "++++    Clinet IP allowed checking --- Failed --- Please make sure Client IP: $client_ip is allowed by this VM by editing /etc/hosts.deny" >> $current_dir/suggestion.txt

        else

                echo "Client IP: $client_ip is not denied by this VM~"
                echo "++++    Client IP: $client_ip is not denied by this VM~" >> $current_dir/report.txt

        fi

}

function check_performance(){

        echo ""
        echo "###############################"
        echo " Now checking the CPU loading~"
        echo "###############################"
        echo ""

        #CPU usage and loading
        echo "---------------------------------------"
                i=1
                while [[ $i -le 1 ]]; do
                    echo -e "\033[32m  Reference${i}\033[0m"
                    UTIL=`vmstat |awk '{if(NR==3)print 100-$15"%"}'`
                    USER=`vmstat |awk '{if(NR==3)print $13"%"}'`
                    SYS=`vmstat |awk '{if(NR==3)print $14"%"}'`
                    IOWAIT=`vmstat |awk '{if(NR==3)print $16"%"}'`
                    echo "Util: $UTIL"
                    echo "++++    CPU Util: $UTIL" >> $current_dir/report.txt
                    echo "User use: $USER"
                    echo "++++    CPU User use: $USER" >> $current_dir/report.txt
                    echo "System use: $SYS"
                    echo "++++    CPU System use: $SYS" >> $current_dir/report.txt
                    echo "I/O wait: $IOWAIT"
                    echo "++++    I/O wait: $IOWAIT" >> $current_dir/report.txt
                    i=$(($i+1))
                    sleep 1
                done
        echo "---------------------------------------"


        echo ""
        echo "#############################"
        echo " Now checking the Mem Usage~"
        echo "#############################"
        echo ""

                #Memory Usage
        echo "---------------------------------------"
                MEM_TOTAL=`free -m |awk '{if(NR==2)printf "%.1f",$2/1024}END{print "G"}'`
                USE=`free -m |awk '{if(NR==3) printf "%.1f",$3/1024}END{print "G"}'`
                FREE=`free -m |awk '{if(NR==3) printf "%.1f",$4/1024}END{print "G"}'`
                CACHE=`free -m |awk '{if(NR==2) printf "%.1f",($6+$7)/1024}END{print "G"}'`
                echo -e "Total: $MEM_TOTAL"
                echo -e "++++    Mem Total: $MEM_TOTAL" >> $current_dir/report.txt
                echo -e "Use: $USE"
                echo -e "++++    Mem Use: $USE" >> $current_dir/report.txt
                echo -e "Free: $FREE"
                echo -e "++++    Mem Free: $FREE" >> $current_dir/report.txt
                echo -e "Cache: $CACHE"
                echo -e "++++    Mem Cache: $CACHE" >> $current_dir/report.txt
        echo "---------------------------------------"


}

function check_pam(){

        echo ""
        echo "#########################################"
        echo "Now checking PAM authentication failure~"
        echo "#########################################"
        echo ""

        if [ $os_flag == r ]; then

                ssh_log=secure
        else

                ssh_log=auth.log

        fi

        pam_status=$(cat /var/log/$ssh_log | grep pam_unix\(sshd\:auth\)\:\ authentication\ failure | grep user=$username)

        if [ -z "$pam_status" ]; then

                echo "There is no PAM authentication issue for user $username~"
                echo "++++    There is no PAM authentication issue for user $username~" >> $current_dir/report.txt

        else

                echo "PAM authentication issue detected for user $username!"
                echo "++++    PAM authentication issue detected for user $username!" >> $current_dir/report.txt
                echo "++++    PAM status checking --- Failed --- Please check PAM related configuration!" >> $current_dir/suggestion.txt

        fi

}

function print_report(){


        echo ""
        echo "##################################"
        echo "Now printing the summary report~"
        echo "##################################"
        echo ""

        echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"

        cat $current_dir/report.txt

        echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"

        rm -rf $current_dir/report.txt


}

function suggestion(){


        echo ""
        echo "############################"
        echo "Now providing suggestions~"
        echo "############################"
        echo ""

        echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        echo "++++"


        if [ ! -f "$current_dir/suggestion.txt" ];then

                echo "++++    No major issue were found yet, please engage with Microsoft Support for further investigation if issue remains" >> $current_dir/suggestion.txt

	fi
        cat $current_dir/suggestion.txt


        echo "++++"
        echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"

        rm -rf $current_dir/suggestion.txt
}

check_network(){

        echo ""
        echo "######################"
        echo " Now checking layer 2~"
        echo "######################"
        echo ""

        layer2_status=$(arp -a)

        if [ "$layer2_status"=~"12:34:56:78:9a:bc" ]; then

                echo "Layer2 network is good~"
		echo "++++    Layer2 network is good~" >> $current_dir/report.txt

        else

                echo "Problem detected in layer2 network!"
                echo "++++    Problem detected in layer2 newtork!" >> $current_dir/report.txt
                echo "++++    Layer2 network checking --- Failed --- Please contact Microsoft Support Professional for further investigation!" >> $current_dir/suggestion.txt

        fi

        echo ""
        echo "######################"
        echo " Now checking layer 3~"
        echo "######################"
        echo ""

        if [ $os_flag == "r" ]; then

                vm_ip=$(ifconfig eth0 | sed -n '2p' | awk '{print $2}')

        else

                vm_ip=$(ifconfig eth0 | sed -n '2p' | awk '{print $2}' | awk -F':' '{print $2}')

        fi

        echo "VM private IP is: $vm_ip"
        echo "++++    VM private IP is: $vm_ip" >> $current_dir/report.txt

        gateway_1=$(echo $vm_ip | awk -F'.' '{print $1}')
        gateway_2=$(echo $vm_ip | awk -F'.' '{print $2}')
        gateway_3=$(echo $vm_ip | awk -F'.' '{print $3}')

        sp="."
        ad="0"

        destination=$gateway_1$sp$gateway_2$sp$gateway_3$sp$ad

        layer3_status=$(route | grep $destination)

        if [ -z "$layer3_status" ]; then

                echo "Problem detected in layer3 newtork!"
                echo "++++    Problem detected in layer3 newtork!" >> $current_dir/report.txt
                echo "++++    Layer3 network checking --- Failed --- Please check dhcp service status or other related networking configuration!" >> $current_dir/suggestion.txt

        else

                echo "Layer3 network is good~"
                echo "++++    Layer3 network is good~" >> $current_dir/report.txt
                check_traffic

        fi

}
function check_ssh_host_ecdsa_key_permission(){


        echo ""
        echo "####################################################"
        echo "Now checking the file /etc/ssh/ssh_host_ecdsa_key~"
        echo "####################################################"
        echo ""


        permission_output=$(ls -l /etc/ssh | grep ssh_host_ecdsa_key | sed -e '/pub/d')
        folder_g=$(echo $permission_output | awk '{print $3}')
        folder_u=$(echo $permission_output | awk '{print $4}')
        folder_p=$(echo $permission_output | awk '{print $1}')

        p1=$(echo $folder_p | awk '{print substr($1,2,1)}')
        p2=$(echo $folder_p | awk '{print substr($1,3,1)}')
        p3=$(echo $folder_p | awk '{print substr($1,4,1)}')

        p4=$(echo $folder_p | awk '{print substr($1,5,1)}')
        p5=$(echo $folder_p | awk '{print substr($1,6,1)}')
        p6=$(echo $folder_p | awk '{print substr($1,7,1)}')

        p7=$(echo $folder_p | awk '{print substr($1,8,1)}')
        p8=$(echo $folder_p | awk '{print substr($1,9,1)}')
        p9=$(echo $folder_p | awk '{print substr($1,10,1)}')

        A=($p1 $p2 $p3 $p4 $p5 $p6 $p7 $p8 $p9)
        len_p=${#A[*]}

        for((i=0;i<$len_p;i++))

        do

                if [ ${A[$i]} == "r" ]; then

                        A[$i]=4

                elif [ ${A[$i]} == "w" ]; then

                        A[$i]=2

                elif [ ${A[$i]} == "x" ]; then

                        A[$i]=1

                else

                        A[$i]=0

                fi

        done

        userselfsum=$((${A[0]}+${A[1]}+${A[2]}))
        usersamegroupsum=$((${A[3]}+${A[4]}+${A[5]}))
        userothergroupsum=$((${A[6]}+${A[7]}+${A[8]}))

        permission_username=${userselfsum}${usersamegroupsum}${userothergroupsum}

        echo "The Permisson of file /etc/ssh/ssh_host_ecdsa_key is $permission_username"
        echo "++++    The Permisson of file /etc/ssh/ssh_host_ecdsa_key is $permission_username" >> $current_dir/report.txt
        echo "The Group of file /etc/ssh/ssh_host_ecdsa_key is $folder_g"
        echo "++++    The Group of file /etc/ssh/ssh_host_ecdsa_key is $folder_g" >> $current_dir/report.txt
        echo "The Owner of file /etc/ssh/ssh_host_ecdsa_key is $folder_u"
        echo "++++    The Owner of file /etc/ssh/ssh_host_ecdsa_key is $folder_u" >> $current_dir/report.txt

        if [ "$os_flag" == "u" ] && [ $permission_username != "600" ]; then

                echo "++++    File /etc/ssh/ssh_host_ecdsa_key permission checking --- Failed --- Please make sure the perssion is 600!" >> $current_dir/suggestion.txt

        elif [ "$os_flag" == "r" ] && [ $permission_username != "640" ]; then

                echo "++++    File /etc/ssh/ssh_host_ecdsa_key permission checking --- Failed --- Please make sure the perssion is 640!" >> $current_dir/suggestion.txt

        else

                echo "Permision of file /etc/ssh/ssh_host_ecdsa_key is good ~"

        fi

}
function check_ssh_host_ed25519_key_permission(){


        echo ""
        echo "####################################################"
        echo "Now checking the file /etc/ssh/ssh_host_ed25519_key~"
        echo "####################################################"
        echo ""


        permission_output=$(ls -l /etc/ssh | grep ssh_host_ed25519_key | sed -e '/pub/d')
        folder_g=$(echo $permission_output | awk '{print $3}')
        folder_u=$(echo $permission_output | awk '{print $4}')
        folder_p=$(echo $permission_output | awk '{print $1}')

        p1=$(echo $folder_p | awk '{print substr($1,2,1)}')
        p2=$(echo $folder_p | awk '{print substr($1,3,1)}')
        p3=$(echo $folder_p | awk '{print substr($1,4,1)}')

        p4=$(echo $folder_p | awk '{print substr($1,5,1)}')
        p5=$(echo $folder_p | awk '{print substr($1,6,1)}')
        p6=$(echo $folder_p | awk '{print substr($1,7,1)}')

        p7=$(echo $folder_p | awk '{print substr($1,8,1)}')
        p8=$(echo $folder_p | awk '{print substr($1,9,1)}')
        p9=$(echo $folder_p | awk '{print substr($1,10,1)}')

        A=($p1 $p2 $p3 $p4 $p5 $p6 $p7 $p8 $p9)
        len_p=${#A[*]}

        for((i=0;i<$len_p;i++))

        do

                if [ ${A[$i]} == "r" ]; then

                        A[$i]=4

                elif [ ${A[$i]} == "w" ]; then

                        A[$i]=2

                elif [ ${A[$i]} == "x" ]; then

                        A[$i]=1

                else

                        A[$i]=0

                fi

        done

        userselfsum=$((${A[0]}+${A[1]}+${A[2]}))
        usersamegroupsum=$((${A[3]}+${A[4]}+${A[5]}))
        userothergroupsum=$((${A[6]}+${A[7]}+${A[8]}))

        permission_username=${userselfsum}${usersamegroupsum}${userothergroupsum}

        echo "The Permisson of file /etc/ssh/ssh_host_ed25519_key is $permission_username"
        echo "++++    The Permisson of file /etc/ssh/ssh_host_ed25519_key is $permission_username" >> $current_dir/report.txt
        echo "The Group of file /etc/ssh/ssh_host_ed25519_key is $folder_g"
        echo "++++    The Group of file /etc/ssh/ssh_host_ed25519_key is $folder_g" >> $current_dir/report.txt
        echo "The Owner of file /etc/ssh/ssh_host_ed25519_key is $folder_u"
        echo "++++    The Owner of file /etc/ssh/ssh_host_ed25519_key is $folder_u" >> $current_dir/report.txt

        if [ "$os_flag" == "u" ] && [ $permission_username != "600" ]; then

                echo "++++    File /etc/ssh/ssh_host_ed25519_key permission checking --- Failed --- Please make sure the perssion is 600!" >> $current_dir/suggestion.txt

        elif [ "$os_flag" == "r" ] && [ $permission_username != "640" ]; then

                echo "++++    File /etc/ssh/ssh_host_ed25519_key permission checking --- Failed --- Please make sure the perssion is 640!" >> $current_dir/suggestion.txt

        else

                echo "Permision of file /etc/ssh/ssh_host_ed25519_key is good ~"

        fi

}
function check_ssh_host_rsa_key_permission(){


        echo ""
        echo "####################################################"
        echo "Now checking the file /etc/ssh/ssh_host_rsa_key~"
        echo "####################################################"
        echo ""


        permission_output=$(ls -l /etc/ssh | grep ssh_host_rsa_key | sed -e '/pub/d')
        folder_g=$(echo $permission_output | awk '{print $3}')
        folder_u=$(echo $permission_output | awk '{print $4}')
        folder_p=$(echo $permission_output | awk '{print $1}')

        p1=$(echo $folder_p | awk '{print substr($1,2,1)}')
        p2=$(echo $folder_p | awk '{print substr($1,3,1)}')
        p3=$(echo $folder_p | awk '{print substr($1,4,1)}')

        p4=$(echo $folder_p | awk '{print substr($1,5,1)}')
        p5=$(echo $folder_p | awk '{print substr($1,6,1)}')
        p6=$(echo $folder_p | awk '{print substr($1,7,1)}')

        p7=$(echo $folder_p | awk '{print substr($1,8,1)}')
        p8=$(echo $folder_p | awk '{print substr($1,9,1)}')
        p9=$(echo $folder_p | awk '{print substr($1,10,1)}')

        A=($p1 $p2 $p3 $p4 $p5 $p6 $p7 $p8 $p9)
        len_p=${#A[*]}

        for((i=0;i<$len_p;i++))

        do

                if [ ${A[$i]} == "r" ]; then

                        A[$i]=4

                elif [ ${A[$i]} == "w" ]; then

                        A[$i]=2

                elif [ ${A[$i]} == "x" ]; then

                        A[$i]=1

                else

                        A[$i]=0

                fi

        done

        userselfsum=$((${A[0]}+${A[1]}+${A[2]}))
        usersamegroupsum=$((${A[3]}+${A[4]}+${A[5]}))
        userothergroupsum=$((${A[6]}+${A[7]}+${A[8]}))

        permission_username=${userselfsum}${usersamegroupsum}${userothergroupsum}

        echo "The Permisson of file /etc/ssh/ssh_host_rsa_key is $permission_username"
        echo "++++    The Permisson of file /etc/ssh/ssh_host_rsa_key is $permission_username" >> $current_dir/report.txt
        echo "The Group of file /etc/ssh/ssh_host_rsa_key is $folder_g"
        echo "++++    The Group of file /etc/ssh/ssh_host_rsa_key is $folder_g" >> $current_dir/report.txt
        echo "The Owner of file /etc/ssh/ssh_host_rsa_key is $folder_u"
        echo "++++    The Owner of file /etc/ssh/ssh_host_rsa_key is $folder_u" >> $current_dir/report.txt

        if [ $permission_username != "600" ]; then

                echo "++++    File /etc/ssh/ssh_host_rsa_key permission checking --- Failed --- Please make sure the perssion is 600!" >> $current_dir/suggestion.txt

        else

                echo "Permision of file /etc/ssh/ssh_host_rsa_key is good ~"

        fi

}
function check_selinux(){

echo "++++++++++++888888888888888+++++++++++++++++"

echo $ssh_running_port
echo $ssh_port

if [[ "$ssh_running_port" != "22" ]] || [[ "$ssh_port" != "22" ]]; then

if [ -f "/etc/selinux/config" ];then
	selinux_status=$(cat /etc/selinux/config | grep SELINUX= | sed -e '/#/d')
	if [[ "$selinux_status" =~ "enforcing" ]]; then

		echo "SELINUX has been enabled on this VM"
                echo "++++    Please consider using command semanage port -l to check if customized port has been allowded by SELINUX" >> $current_dir/suggestion.txt
                echo "++++    If semanage command is not supported on this VM, please considering installing package setroubleshoot-server and selinux-policy-devel" >> $current_dir/suggestion.txt

	else 

		echo "SELINUX is not enabled on this VM"
		echo "++++    SELINUX is not enabled on this VM" >> $current_dir/report.txt

	fi
else 

	echo "SELINUX is not installed on this VM"
	echo "++++    SELINUX is not installed on this VM" >> $current_dir/report.txt

fi

fi

}

function check_var_empty_sshd(){


		if [ "$os_flag" == "r" ]; then


        echo ""
        echo "####################################################"
        echo "Now checking the folder /var/empty/sshd~"
        echo "####################################################"
        echo ""


        permission_output=$(ls -l /var/empty | grep sshd)
        folder_g=$(echo $permission_output | awk '{print $3}')
        folder_u=$(echo $permission_output | awk '{print $4}')
        folder_p=$(echo $permission_output | awk '{print $1}')

        p1=$(echo $folder_p | awk '{print substr($1,2,1)}')
        p2=$(echo $folder_p | awk '{print substr($1,3,1)}')
        p3=$(echo $folder_p | awk '{print substr($1,4,1)}')

        p4=$(echo $folder_p | awk '{print substr($1,5,1)}')
        p5=$(echo $folder_p | awk '{print substr($1,6,1)}')
        p6=$(echo $folder_p | awk '{print substr($1,7,1)}')

        p7=$(echo $folder_p | awk '{print substr($1,8,1)}')
        p8=$(echo $folder_p | awk '{print substr($1,9,1)}')
        p9=$(echo $folder_p | awk '{print substr($1,10,1)}')

        A=($p1 $p2 $p3 $p4 $p5 $p6 $p7 $p8 $p9)
        len_p=${#A[*]}

        for((i=0;i<$len_p;i++))

        do

                if [ ${A[$i]} == "r" ]; then

                        A[$i]=4

                elif [ ${A[$i]} == "w" ]; then

                        A[$i]=2

                elif [ ${A[$i]} == "x" ]; then

                        A[$i]=1

                else

                        A[$i]=0

                fi

        done

        userselfsum=$((${A[0]}+${A[1]}+${A[2]}))
        usersamegroupsum=$((${A[3]}+${A[4]}+${A[5]}))
        userothergroupsum=$((${A[6]}+${A[7]}+${A[8]}))

        permission_username=${userselfsum}${usersamegroupsum}${userothergroupsum}

        echo "The Permisson of folder /var/empty/sshd is $permission_username"
        echo "++++    The Permisson of folder /var/empty/sshd is $permission_username" >> $current_dir/report.txt
        echo "The Group of folder /var/empty/sshd is $folder_g"
        if [ $permission_username != "711" ]; then

                echo "++++    Folder /var/empty/sshd checking --- Failed --- Please make sure the perssion is 711!" >> $current_dir/suggestion.txt

        else

                echo "Permision of Folder /var/empty/sshd is good ~"

        fi

		fi

}

check_etc_pamd_sshd(){


	if [ "$os_flag" == "r" ]; then


        echo ""
        echo "####################################################"
        echo "Now checking the fifle /etc/pam.d/sshd~"
        echo "####################################################"
        echo ""

	pamd_sshd_substack=$(cat /etc/pam.d/sshd | grep password-auth | grep substack | sed -e '/#/d' | sed -e '/session/d')
	pamd_sshd_account=$(cat /etc/pam.d/sshd | grep password-auth | grep account | sed -e '/#/d' | sed -e '/session/d')
	pamd_sshd_password=$(cat /etc/pam.d/sshd | grep password-auth | grep password-auth | sed -e '/#/d' | sed -e '/session/d' | sed -e '/substack/d' | sed -e '/account/d' | awk '{print $1}')


	if [[ !("$pamd_sshd_substack" =~ "substack") ]]; then

		echo "Substack setting not found in file /etc/pam.d/sshd"
		echo "++++    File /etc/pam.d/sshd checking --- Failed --- Please make sure substack is enabled" >> $current_dir/suggestion.txt

	fi
	if [[ !("$pamd_sshd_account" =~ "account") ]]; then

		echo "Account setting not found in file /etc/pam.d/sshd"
		echo "++++    File /etc/pam.d/sshd checking --- Failed --- Please make sure account is enabled" >> $current_dir/suggestion.txt

	fi
	if [[ !("$pamd_sshd_password" = "password") ]]; then

		echo "Password setting not found in file /etc/pam.d/sshd"
		echo "++++    File /etc/pam.d/sshd checking --- Failed --- Please make sure password is enabled" >> $current_dir/suggestion.txt

	fi

	fi


}

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
