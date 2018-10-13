#!/bin/bash

# arguments: $RELEASE $LINUXFAMILY $BOARD $BUILD_DESKTOP
#
# This is the image customization script

# NOTE: It is copied to /tmp directory inside the image
# and executed there inside chroot environment
# so don't reference any files that are not already installed

# NOTE: If you want to transfer files between chroot and host
# userpatches/overlay directory on host is bind-mounted to /tmp/overlay in chroot

RELEASE=$1
LINUXFAMILY=$2
BOARD=$3
BUILD_DESKTOP=$4

Main() {
	case $RELEASE in
		jessie)
			# your code here
			# InstallOpenMediaVault # uncomment to get an OMV 3 image
			;;
		xenial)
			InstallIoTHub;
			;;
		stretch)
			# your code here
			# InstallOpenMediaVault # uncomment to get an OMV 4 image
			;;
	esac
} # Main

InstallIoTHub() {
	# This will install Nginx, Mysql, PHP, phpmyadmin, mosquitto and nodered.
	# Nodered will be mounted on / in Nginx and phpmyadmin on /phpmyadmin.
	
	export LANG=C LC_ALL="en_US.UTF-8"
	export DEBIAN_FRONTEND="noninteractive"
	chage -d 999999 root #set root password to not expiring now
	rm /etc/resolv.conf 
	ln -s /run/resolvconf/resolv.conf /etc/resolv.conf
	resolvconf --enable-updates
	echo "nameserver 192.168.122.1" >> /etc/resolv.conf
	apt-get --yes --force-yes install pwgen debconf-utils html2text dirmngr armbian-config libassuan0 libnpth0 libksba8
	PHPMYADMIN_PASS=$(pwgen 10 1)
	debconf-set-selections <<< "mysql-server mysql-server/root_password password 12345678"
	debconf-set-selections <<< "mysql-server mysql-server/root_password_again password 12345678"
	debconf-set-selections <<< "phpmyadmin phpmyadmin/dbconfig-install boolean false"
	debconf-set-selections <<< "phpmyadmin phpmyadmin/mysql/app-pass password $PHPMYADMIN_PASS"
	debconf-set-selections <<< "phpmyadmin phpmyadmin/app-password-confirm password $PHPMYADMIN_PASS"
	debconf-set-selections <<< "phpmyadmin phpmyadmin/admin-pass password 12345678"
	debconf-set-selections <<< "phpmyadmin phpmyadmin/reconfigure-webserver multiselect"
	#Add node-red debian repos, including gnupg key
	apt-get --yes --force-yes purge network-manager
	apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 68576280
	sudo add-apt-repository -y ppa:ondrej/php

	cat > /etc/apt/sources.list.d/nodesource.list <<- EOF
	deb https://deb.nodesource.com/node_8.x ${RELEASE} main
	deb-src https://deb.nodesource.com/node_8.x ${RELEASE} main
	EOF

	#Modify amrbianEnv
	echo "disp_dvi_compat=1" >> /boot/armbianEnv.txt

	#Install packages
	apt-get update
	echo "=============             Installing mariadb            ============="
	apt-get install --yes --force-yes mariadb-server
	#/bin/bash # drop to a shell
	echo "============= Setting up mariadb root user and password ============="
	mysqld_safe --skip-networking &
	sleep 10
	mysql --user=root mysql <<- EOF
SET PASSWORD FOR 'root'@'localhost' = PASSWORD('12345678');
UPDATE mysql.user SET plugin = 'mysql_native_password' WHERE user = 'root' AND plugin = 'unix_socket';
FLUSH PRIVILEGES;
EOF
	#/bin/bash #drop into a shell
	echo "=============         Installing other packages         ============="
	apt-get --yes --force-yes \
		-o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install \
		php-fpm php nginx-full php-mysql phpmyadmin composer php-cli php-gd php-curl nodejs mosquitto dnsmasq hostapd iptables sed vim aptitude
	#/bin/bash #Use this to drop into a shell

	echo "=============            Installing Node-RED            ============="
	#Install node-red
	npm install --unsafe -g node-red node-red-dashboard node-red-contrib-sqldbs node-red-contrib-alexa \
		node-red-contrib-chatbot node-red-contrib-http-request node-red-node-twitter node-red-contrib-config node-red-admin

	echo "=============   Configuring hostapd, nginx and dnsmasq   ============="
	#Setup config of nginx and add nodered service file
	cp /tmp/overlay/nginx_phpmyadmin.conf /etc/nginx/snippets/phpmyadmin.conf
	cp /tmp/overlay/nginx_default /etc/nginx/sites-available/default
	cp /tmp/overlay/nodered.service /etc/systemd/system/
	cp /tmp/overlay/hostapd.conf /etc/hostapd.conf
	cp /tmp/overlay/dnsmasq.conf /etc/dnsmasq.conf
	cp /tmp/overlay/dnsmasq.service /lib/systemd/system


	sed -i -e "s/^# en_PH.UTF-8 UTF-8/en_PH.UTF-8 UTF-8/" /etc/locale.gen
	/usr/sbin/locale-gen

	#Add iptables to rc.local.
	sed -i '/exit 0/d' /etc/rc.local
	cat >> /etc/rc.local <<- EOF
	iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
	iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
	exit 0
	EOF

	#Allow ip forwarding
	echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/ip_forward.conf

	#Add users and groups
	addgroup --system nodered
	adduser --system --home /srv/nodered --shell /bin/false --group nodered 

	#Restart services
	systemctl enable nodered
	systemctl enable dnsmasq
	systemctl enable nginx
	systemctl enable mysql
	chage -d 0 root #expire root password again

	#Copy node-red config
	mkdir -p /srv/nodered/.node-red
	cp /tmp/overlay/settings.js /srv/nodered/.node-red/settings.js
	cp /tmp/overlay/flows_iot.json /srv/nodered/.node-red/
	chown nodered:nodered /srv/nodered/.node-red -R
	
	# Final network steps
	cp /tmp/overlay/wlan0_interface /etc/network/interfaces.d/wlan0
	cp /tmp/overlay/eth0_interface /etc/network/interfaces.d/eth0
	sed -i -e "s/^#DAEMON_CONF=.*/DAEMON_CONF=\"\/etc\/hostapd.conf\"/" /etc/default/hostapd
	sed -i -e "s/^#auto wlan0/auto wlan0/" /etc/network/interfaces.d/wlan0
	sed -i -e "s/^#//" /etc/dnsmasq.conf
	/bin/bash #Drop into a shell


}

InstallOpenMediaVault() {
	# use this routine to create a Debian based fully functional OpenMediaVault
	# image (OMV 3 on Jessie, OMV 4 with Stretch). Use of mainline kernel highly
	# recommended!
	#
	# Please note that this variant changes Armbian default security 
	# policies since you end up with root password 'openmediavault' which
	# you have to change yourself later. SSH login as root has to be enabled
	# through OMV web UI first
	#
	# This routine is based on idea/code courtesy Benny Stark. For fixes,
	# discussion and feature requests please refer to
	# https://forum.armbian.com/index.php?/topic/2644-openmediavault-3x-customize-imagesh/

	echo root:openmediavault | chpasswd
	rm /root/.not_logged_in_yet
	. /etc/default/cpufrequtils
	export LANG=C LC_ALL="en_US.UTF-8"

	case ${RELEASE} in
		jessie)
			OMV_Name="erasmus"
			OMV_EXTRAS_URL="https://github.com/OpenMediaVault-Plugin-Developers/packages/raw/master/openmediavault-omvextrasorg_latest_all3.deb"
			;;
		stretch)
			OMV_Name="arrakis"
			OMV_EXTRAS_URL="https://github.com/OpenMediaVault-Plugin-Developers/packages/raw/master/openmediavault-omvextrasorg_latest_all4.deb"
			;;
	esac

	#Add OMV source.list and Update System
	cat > /etc/apt/sources.list.d/openmediavault.list <<- EOF
	deb https://openmediavault.github.io/packages/ ${OMV_Name} main
	## Uncomment the following line to add software from the proposed repository.
	deb https://openmediavault.github.io/packages/ ${OMV_Name}-proposed main
	
	## This software is not part of OpenMediaVault, but is offered by third-party
	## developers as a service to OpenMediaVault users.
	# deb https://openmediavault.github.io/packages/ ${OMV_Name} partner
	EOF

	# Add OMV and OMV Plugin developer keys, add Cloudshell 2 repo for XU4
	if [ "${BOARD}" = "odroidxu4" ]; then
		add-apt-repository -y ppa:kyle1117/ppa
		sed -i 's/jessie/xenial/' /etc/apt/sources.list.d/kyle1117-ppa-jessie.list
	fi
	mount --bind /dev/null /proc/mdstat
	apt-get update
	apt-get --yes --force-yes --allow-unauthenticated install openmediavault-keyring
	apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 7AA630A1EDEE7D73

	# install debconf-utils, postfix and OMV
	HOSTNAME="${BOARD}"
	debconf-set-selections <<< "postfix postfix/mailname string ${HOSTNAME}"
	debconf-set-selections <<< "postfix postfix/main_mailer_type string 'No configuration'"
	apt-get --yes --force-yes --allow-unauthenticated  --fix-missing --no-install-recommends \
		-o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install \
		debconf-utils postfix
	# move newaliases temporarely out of the way (see Ubuntu bug 1531299)
	cp -p /usr/bin/newaliases /usr/bin/newaliases.bak && ln -sf /bin/true /usr/bin/newaliases
	sed -i -e "s/^::1         localhost.*/::1         ${HOSTNAME} localhost ip6-localhost ip6-loopback/" \
		-e "s/^127.0.0.1   localhost.*/127.0.0.1   ${HOSTNAME} localhost/" /etc/hosts
	sed -i -e "s/^mydestination =.*/mydestination = ${HOSTNAME}, localhost.localdomain, localhost/" \
		-e "s/^myhostname =.*/myhostname = ${HOSTNAME}/" /etc/postfix/main.cf
	export DEBIAN_FRONTEND=noninteractive
	apt-get --yes --force-yes --allow-unauthenticated  --fix-missing --no-install-recommends \
		-o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install \
		openmediavault

	# install OMV extras, enable folder2ram, zram, tweak some settings
	FILE=$(mktemp)
	wget "$OMV_EXTRAS_URL" -qO $FILE && dpkg -i $FILE
	wget https://mirrors.kernel.org/ubuntu/pool/universe/z/zram-config/zram-config_0.5_all.deb -qO $FILE && dpkg -i $FILE

	/usr/sbin/omv-update
	# Install flashmemory plugin and netatalk by default, use nice logo for the latter,
	# tweak some OMV settings
	. /usr/share/openmediavault/scripts/helper-functions
	apt-get -y -q install openmediavault-netatalk openmediavault-flashmemory
	AFP_Options="mimic model = Macmini"
	SMB_Options="min receivefile size = 16384\nwrite cache size = 524288\ngetwd cache = yes\nsocket options = TCP_NODELAY IPTOS_LOWDELAY"
	xmlstarlet ed -L -u "/config/services/afp/extraoptions" -v "$(echo -e "${AFP_Options}")" /etc/openmediavault/config.xml
	xmlstarlet ed -L -u "/config/services/smb/extraoptions" -v "$(echo -e "${SMB_Options}")" /etc/openmediavault/config.xml
	xmlstarlet ed -L -u "/config/services/flashmemory/enable" -v "1" /etc/openmediavault/config.xml
	xmlstarlet ed -L -u "/config/services/ssh/enable" -v "1" /etc/openmediavault/config.xml
	xmlstarlet ed -L -u "/config/services/ssh/permitrootlogin" -v "0" /etc/openmediavault/config.xml
	xmlstarlet ed -L -u "/config/system/time/ntp/enable" -v "1" /etc/openmediavault/config.xml
	xmlstarlet ed -L -u "/config/system/time/timezone" -v "UTC" /etc/openmediavault/config.xml
	xmlstarlet ed -L -u "/config/system/network/dns/hostname" -v "${HOSTNAME}" /etc/openmediavault/config.xml
	xmlstarlet ed -L -u "/config/system/monitoring/perfstats/enable" -v "0" /etc/openmediavault/config.xml
	echo -e "OMV_CPUFREQUTILS_GOVERNOR=${GOVERNOR}" >>/etc/default/openmediavault
	echo -e "OMV_CPUFREQUTILS_MINSPEED=${MIN_SPEED}" >>/etc/default/openmediavault
	echo -e "OMV_CPUFREQUTILS_MAXSPEED=${MAX_SPEED}" >>/etc/default/openmediavault
	for i in netatalk samba flashmemory ssh ntp timezone interfaces cpufrequtils monit collectd rrdcached ; do
		/usr/sbin/omv-mkconf $i
	done
	systemctl disable log2ram
	rm /etc/cron.daily/log2ram
	/sbin/folder2ram -enablesystemd || true
	sed -i 's|-j /var/lib/rrdcached/journal/ ||' /etc/init.d/rrdcached

	#FIX TFTPD ipv4
	[ -f /etc/default/tftpd-hpa ] && sed -i 's/--secure/--secure --ipv4/' /etc/default/tftpd-hpa

	# rootfs resize to 7.3G max and adding omv-initsystem to firstrun -- q&d but shouldn't matter
	echo 15500000s >/root/.rootfs_resize
	sed -i '/systemctl\ disable\ firstrun/i \
	mv /usr/bin/newaliases.bak /usr/bin/newaliases \
	export DEBIAN_FRONTEND=noninteractive \
	sleep 3 \
	apt-get install -f -qq python-pip || exit 0 \
	pip install -U tzupdate \
	tzupdate \
	read TZ </etc/timezone \
	/usr/sbin/omv-initsystem \
	xmlstarlet ed -L -u "/config/system/time/timezone" -v "${TZ}" /etc/openmediavault/config.xml \
	/usr/sbin/omv-mkconf timezone \
	lsusb | egrep -q "0b95:1790|0b95:178a|0df6:0072" || sed -i "/ax88179_178a/d" /etc/modules' /etc/init.d/firstrun
	sed -i '/systemctl\ disable\ firstrun/a \
	sleep 30 && sync && reboot' /etc/init.d/firstrun

	# add USB3 Gigabit Ethernet support
	echo -e "r8152\nax88179_178a" >>/etc/modules

	# Special treatment for ODROID-XU4 (and later Amlogic S912, RK3399 and other big.LITTLE
	# based devices). Move all NAS daemons to the big cores.
	# to 1MB: https://forum.odroid.com/viewtopic.php?f=146&t=26016&start=200#p197729
	if [ "${BOARD}" = "odroidxu4" ]; then
		HMP_Fix='; taskset -c -p 4-7 $i '
		# Cloudshell stuff (fan, lcd, missing serials on 1st CS2 batch)
		echo "H4sIAKdXHVkCA7WQXWuDMBiFr+eveOe6FcbSrEIH3WihWx0rtVbUFQqCqAkYGhJn
		tF1x/vep+7oebDfh5DmHwJOzUxwzgeNIpRp9zWRegDPznya4VDlWTXXbpS58XJtD
		i7ICmFBFxDmgI6AXSLgsiUop54gnBC40rkoVA9rDG0SHHaBHPQx16GN3Zs/XqxBD
		leVMFNAz6n6zSWlEAIlhEw8p4xTyFtwBkdoJTVIJ+sz3Xa9iZEMFkXk9mQT6cGSQ
		QL+Cr8rJJSmTouuuRzfDtluarm1aLVHksgWmvanm5sbfOmY3JEztWu5tV9bCXn4S
		HB8RIzjoUbGvFvPw/tmr0UMr6bWSBupVrulY2xp9T1bruWnVga7DdAqYFgkuCd3j
		vORUDQgej9HPJxmDDv+3WxblBSuYFH8oiNpHz8XvPIkU9B3JVCJ/awIAAA==" \
		| tr -d '[:blank:]' | base64 --decode | gunzip -c >/usr/local/sbin/cloudshell2-support.sh
		chmod 755 /usr/local/sbin/cloudshell2-support.sh
		apt install -y i2c-tools odroid-cloudshell cloudshell2-fan
		sed -i '/systemctl\ disable\ firstrun/i \
		lsusb | grep -q -i "05e3:0735" && sed -i "/exit\ 0/i echo 20 > /sys/class/block/sda/queue/max_sectors_kb" /etc/rc.local \
		/usr/sbin/i2cdetect -y 1 | grep -q "60: 60" && /usr/local/sbin/cloudshell2-support.sh' /etc/init.d/firstrun
	elif [ "${BOARD}" = "nanopim3" ]; then
		HMP_Fix='; taskset -c -p 4-7 $i '
	fi
	echo "* * * * * root for i in \`pgrep \"ftpd|nfsiod|smbd|afpd|cnid\"\` ; do ionice -c1 -p \$i ${HMP_Fix}; done >/dev/null 2>&1" \
		>/etc/cron.d/make_nas_processes_faster
	chmod 600 /etc/cron.d/make_nas_processes_faster

	# add SATA port multiplier hint if appropriate
	[ "${LINUXFAMILY}" = "sunxi" ] && \
		echo -e "#\n# If you want to use a SATA PM add \"ahci_sunxi.enable_pmp=1\" to bootargs above" \
		>>/boot/boot.cmd

	# Update smartmontools drive database
	wget https://raw.githubusercontent.com/mirror/smartmontools/master/drivedb.h -qO $FILE
	grep -q 'drivedb.h' $FILE && mv $FILE /var/lib/smartmontools/drivedb/drivedb.h && \
		chmod 644 /var/lib/smartmontools/drivedb/drivedb.h

	# Filter out some log messages
	echo ':msg, contains, "do ionice -c1" ~' >/etc/rsyslog.d/omv-armbian.conf
	echo ':msg, contains, "action " ~' >>/etc/rsyslog.d/omv-armbian.conf
	echo ':msg, contains, "netsnmp_assert" ~' >>/etc/rsyslog.d/omv-armbian.conf
	echo ':msg, contains, "Failed to initiate sched scan" ~' >>/etc/rsyslog.d/omv-armbian.conf

	# clean up and force password change on first boot
	umount /proc/mdstat
	chage -d 0 root
} # InstallOpenMediaVault

Main "$@"

