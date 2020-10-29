#!/bin/bash
#
#////////////////////////////////////////////////////////////
#===========================================================
# ts_check.pl - Installer v1.1
# Ruben Calzadilla
#===========================================================
#
# Set environment
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Clear the screen
clear

#SERVERKEY=$1
#GATEWAY=$2
LOG=/var/log/ts_check_installer.log

echo "-----------------------------------"
echo " Welcome to the ts_check Installer"
echo " Installing ts_check.pl v0.7"
echo "-----------------------------------"
echo " "

# Are we running as root
if [ $(id -u) != "0" ]; then
	echo "ts_check installer needs to be run with root priviliges"
	echo "Try again with root privilileges"
	echo " "
	exit 1;
fi

# Do we have Internet access
timeout 3 ping -c1 8.8.8.8 > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
	echo "No Internet access is detected, Please check!"
	echo "We need Internet access to install dependencies"
	echo "and to download the ts_check application"
	echo " "
	exit 1
fi

### install Dependencies here
echo "Installing Dependencies, this may take few minutes"
echo " "
#echo "Identifying OS"

# RHEL / CentOS / etc
if [ -n "$(command -v yum)" ]; then
	yum -y install ncurses-devel cpan gcc make >> $LOG 2>&1

	# Check if perl available or not
	if ! type "perl" >> $LOG 2>&1; then
		yum -y install perl >> $LOG 2>&1
	fi
    
    # Check if wget available or not
	if ! type "wget" >> $LOG 2>&1; then
		yum -y install wget >> $LOG 2>&1
	fi

    #Install Curses
    export PERL_MM_USE_DEFAULT=1
    cpan install Curses >> $LOG 2>&1
    
    # Installing IO::Socket::Multicast
    wget http://52.73.123.68/epel-release-7-12.noarch.rpm >> $LOG 2>&1
    rpm -Uvh epel-release*.rpm >> $LOG 2>&1
    yum -y install perl-IO-Socket-Multicast >> $LOG 2>&1

fi

# Debian / Ubuntu
if [ -n "$(command -v apt-get)" ]; then
	apt-get update -y >> $LOG 2>&1
	apt-get install -y libio-socket-multicast-perl ncurses-dev build-essential gcc >> $LOG 2>&1

	# Check if perl available or not
	if ! type "perl" >> $LOG 2>&1; then
		apt-get install -y perl >> $LOG 2>&1
	fi

	# Check if wget available or not
	if ! type "wget" >> $LOG 2>&1; then
		apt-get install -y wget >> $LOG 2>&1
	fi
    
    #Install Curses
    export PERL_MM_USE_DEFAULT=1
    cpan install Curses >> $LOG 2>&1

fi


### Install ###
wget -O /usr/local/bin/ts_check.pl http://52.73.123.68/ts_check.pl >> $LOG 2>&1

# Did it download ?
if ! [ -f /usr/local/bin/ts_check.pl ]; then
	echo "Unable to install! Source code didnt download"
	echo "Exiting installer"
	echo " "
	exit 1
fi

# Making the script executable and creating a symbolic link
chmod +x /usr/local/bin/ts_check.pl
ln -s /usr/local/bin/ts_check.pl /usr/local/bin/ts_check

echo " "
echo "----------------------------------------"
echo " Installation Completed "
echo " Just type ts_check to call the utility "
echo "----------------------------------------"
echo " "

echo "ts_check"
/usr/local/bin/ts_check

# Attempt to delete this installer
echo "Removing installer"
echo " "
if [ -f $0 ]; then
	rm -f $0
fi
