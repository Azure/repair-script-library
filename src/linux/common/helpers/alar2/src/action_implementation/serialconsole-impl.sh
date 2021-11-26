#!/bin/bash

#
# serialconsole-impl is responsible to set the configuration for the serialconsole
# correct in case this is missing in a VM image.
# It also enables sysreq to allow a reboot from the Portal
#

enable_sysreq() {
    if [[ $isRedHat == "true"  ]]; then
        echo "kernel.sysrq = 1" >> /etc/sysctl.d/90-alar2.conf
    else
        echo "kernel.sysrq = 1" >> /etc/sysctl.conf
    fi
}


serial_fix_suse_redhat (){
    if [[ "$isRedHat6" == "true" ]]; then
        echo "Configuring the serialconsole for RedHat 6.x is not implemented"
        exit 1
    fi

    grub_file="/etc/default/grub"
    enable_sysreq

    if [[ -f $grub_file ]]; then
        sed -i 's/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=30/' $grub_file

	grep -Eq '^GRUB_CMDLINE_LINUX.*' $grub_file
	if [[ $? -eq 0  ]]; then
        	sed -i '/GRUB_CMDLINE_LINUX.*/s/"$//; s|GRUB_CMDLINE_LINUX.*|& console=tty1 console=ttyS0,115200n8 earlyprintk=ttyS0,115200"|' $grub_file
	else
		echo 'GRUB_CMDLINE_LINUX="console=tty1 console=ttyS0,115200n8 earlyprintk=ttyS0,115200"' >> $grub_file
	fi


        # modify terminal
        grep -q 'GRUB_TERMINAL' $grub_file
        if [[ $? -eq 0 ]]; then
            sed -i 's/GRUB_TERMINAL.*/GRUB_TERMINAL="serial"/' $grub_file
        else
            echo 'GRUB_TERMINAL="serial"' >> $grub_file
        fi

        # modify GRUB serial
        grep -q 'GRUB_SERIAL_COMMAND' $grub_file
        if [[ $? -eq 0 ]]; then
            sed -i 's/GRUB_SERIAL_COMMAND.*/GRUB_SERIAL_COMMAND="serial --speed=9600 --unit=0 --word=8 --parity=no --stop=1"/' $grub_file
        else
            echo 'GRUB_SERIAL_COMMAND="serial --speed=9600 --unit=0 --word=8 --parity=no --stop=1"' >> $grub_file
        fi
      
      grep -q 'GRUB_TIMEOUT_STYLE' $grub_file
      if [[ $? -eq 0 ]]; then
           sed -i 's/GRUB_TIMEOUT_STYLE.*//' $grub_file
      fi
    else
        
# file does not exist
touch $grub_file
cat $grub_file << EOF
GRUB_TIMEOUT=30
GRUB_DISTRIBUTOR="$(sed 's, release .*$,,g' /etc/system-release)"
GRUB_DEFAULT=saved
GRUB_DISABLE_SUBMENU=true
GRUB_TERMINAL="serial"
GRUB_CMDLINE_LINUX="console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300"
GRUB_DISABLE_RECOVERY="true"
GRUB_SERIAL_COMMAND="serial --speed=9600 --unit=0 --word=8 --parity=no --stop=1"
EOF
    fi
    # update grub
    if [[ -d /sys/firmware/efi ]]; then 
        if [[ $isRedHat == "true" ]]; then
            grub2-mkconfig -o /boot/efi/EFI/$(grep '^ID=' /etc/os-release | cut -d '"' -f2)/grub.cfg
        fi    
    else
        grub2-mkconfig -o /boot/grub2/grub.cfg
    fi
}

# REDHAT/CENTOS PART
if [[ "$isRedHat" == "true" ]]; then
    serial_fix_suse_redhat
fi

# SUSE PART
if [[ "$isSuse" == "true" ]]; then
    serial_fix_suse_redhat

fi

# UBUNTU PART
# if #1
if [[ "$isUbuntu" == "true" ]]; then
    grub_file="/etc/default/grub.d/50-cloudimg-settings.cfg"
    enable_sysreq
    
    # if #2
    if [[ -f $grub_file ]]; then
        sed -i 's/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=10/' $grub_file
	grep -Eq '^GRUB_CMDLINE_LINUX.*' $grub_file

    # if #3
	if [[ $? -eq 0  ]]; then
        	sed -i '/GRUB_CMDLINE_LINUX.*/s/"$//; s|GRUB_CMDLINE_LINUX.*|& console=tty1 console=ttyS0 earlyprintk=ttyS0"|' $grub_file
	else
		echo 'GRUB_CMDLINE_LINUX="console=tty1 console=ttyS0 earlyprintk=ttyS0"' >> $grub_file
	fi # close if#3

        # modify GRUB serial if required
        grep -q "GRUB_TERMINAL=serial" $grub_file
        
        # if#4
        if [[ $? -ne 0 ]]; then
            echo "GRUB_TERMINAL=serial" >>  $grub_file
        else
        # make a full replacement
            sed -i 's/GRUB_SERIAL_COMMAND.*/GRUB_SERIAL_COMMAND="serial --speed=9600 --unit=0 --word=8 --parity=no --stop=1"/' $grub_file
        fi # close if#4
    else

# file does not exist
touch $grub_file
cat $grub_file << EOF
# Set the default commandline
GRUB_CMDLINE_LINUX="console=tty1 console=ttyS0 earlyprintk=ttyS0"
GRUB_CMDLINE_LINUX_DEFAULT=""

# Set the grub console type
GRUB_TERMINAL=serial

# Set the serial command
GRUB_SERIAL_COMMAND="serial --speed=9600 --unit=0 --word=8 --parity=no --stop=1"

# Set the recordfail timeout
GRUB_RECORDFAIL_TIMEOUT=30

# Wait briefly on grub prompt
GRUB_TIMEOUT=10
EOF
    fi # close if#2
    # update grub
    update-grub
fi # close if#1
