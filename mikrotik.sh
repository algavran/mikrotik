#!/bin/sh
# IP mikrotika kojeg se mijenja
set -u

#echo -n "Enter Mikrotik IP? : "
#read fromip
testdns (){
dnsip="psk223d.duckdns.org
        psk223g.duckdns.org"

while IFS= read -r line
do
#	defip=`timeout 10 ssh -n $line "system identity print"|cut -d " " -f4| tr -d ' '`
	nc -z -w5 $line 53
	defip=`echo $?`

	if [ "$defip" == "0" ]; then
		echo $line connected
		hline=`host $line |grep address |cut -d " " -f4`
		fromip=$hline	
		break
	else
		fromip=0
	fi

done <<< "$dnsip"
}

#sudo su -c /home/mikrotik/mikrotik
fromip=0

	if [ "$fromip" == "0" ]; then

		echo -n "Enter Mikrotik IP? : "
		read fromip
	else
		echo Connected
	fi

# Submenu 1
f_subm1 () {

echo Wait!! testing Connectivity

timeout 10 ssh -y -n root@$fromip "system identity print"|grep -w 'psk223'

defip=`echo $?`

if [ "$defip" == "0" ]; then
echo $fromip connected

echo -n "ID Poslovnice? : "
read pskid
if [ "$pskid" == "" ]; then
echo "Invalid ID ";    
sleep 3
else
grepid=`grep $pskid /root/mikrotik/ipranges`
if [ "$grepid" == "" ]; then
echo "Invalid ID $pskid";    
sleep 3
else

id=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f1`
ip=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f2`
subnet=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f3|cut -d "/" -f1`
net=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f3`
gw=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f4`
pool=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f5`
ovpnip=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f6`
subnet2=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f8`
gw2=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f8|sed 's/0$/1/'`
eoipr=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f7`
eoipl=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f7|sed 's/1$/2/'`
gre=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f7|sed 's/1$/2\/30/'`
TID=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f1|sed 's/psk//'`
net2=$subnet2'/24'
stream=`echo $net|cut -d "." -f1,2,3`


#----------------------------------------------------------------------------------------
while true
do
	 SN=`ssh -n root@$fromip "system license print"|grep software-id|cut -d ":" -f2|cut -c 2- `
	 if [ -n "$SN" ]; then
		 rid=`grep $id /root/mikrotik/Mikrotik_SerialNumbers.db|cut -d "," -f2`

	 	if [ -n "$rid" ]; then
			sed -i "s/.*$pskid.*/$pskid,$SN/g" /root/mikrotik/Mikrotik_SerialNumbers.db & 2> /dev/null
	 		break
	 	else
			sudo echo "$id","$SN" >> /root/mikrotik/Mikrotik_SerialNumbers.db
		 break
	 	fi
	 else
		 echo Empty serial
	 fi
 done
dos2unix < /root/mikrotik/Mikrotik_SerialNumbers.db > /root/mikrotik/Mikrotik_SerialNumbers.db.tmp
mv /root/mikrotik/Mikrotik_SerialNumbers.db.tmp /root/mikrotik/Mikrotik_SerialNumbers.db
#----------------------------------------------------------------------------------------

if grep -w -e "$ovpnip" -e "X$ovpnip" /root/mikrotik/pskdbf/pskdb;then
		 	ln=`grep -w "X$ovpnip" /root/mikrotik/pskdbf/pskdb`
#			sed "s/$ln/$ovpnip/" /root/mikrotik/pskdbf/pskdb
			sudo sed -i "s/$ln/$ovpnip/g" /root/mikrotik/pskdbf/pskdb
		else
			echo $ovpnip >> /root/mikrotik/pskdbf/pskdb
		fi	



#sh /root/mikrotik/pskdbf/hostupdate >/dev/null 2>&1

echo -n " Adsl user? : "
read adsluser
echo -n " Adsl pass? : "
read adslpass

sleep 1
echo ifconfig-push $ovpnip 192.168.40.1 > /etc/openvpn/ccd/$id
echo iroute $subnet 255.255.255.0 >> /etc/openvpn/ccd/$id
echo iroute $subnet2 255.255.255.0 >> /etc/openvpn/ccd/$id
sh /root/mikrotik/pskdbf/hostupdate >/dev/null 2>&1

# rename wlan2
ssh -q root@$fromip "interface wireless set name=wlan1 numbers=0 mode=ap-bridge ssid=PSK wireless-protocol=802.11 security-profile=psk"

# bridge-local address change
ssh -q root@$fromip "ip address set [ find comment=bridge-local ] address=$ip" 2>/dev/null
if ssh -q root@$fromip "ip address print brief" 2>/dev/null |grep -w $ip 1>/dev/null; then echo bridge-local IP update OK!; else echo bridge-local IP update FAILED !!!; fi

ssh -q root@$fromip "ip address set [ find comment=bridge-Ensico ] address=$gw2" 2>/dev/null
if ssh -q root@$fromip "ip address print brief" 2>/dev/null |grep -w $gw2 1>/dev/null; then echo bridge-Ensico IP update OK!; else echo bridge-Ensico IP update FAILED !!!; fi

#Ensico
ssh -q root@$fromip "ip address set [ find comment=gre-tunnel ] address=$gre" 2>/dev/null
if ssh -q root@$fromip "ip address print brief" 2>/dev/null |grep -w $gre 1>/dev/null; then echo gre_tunnel IP update OK!; else echo gre_tunnel IP update FAILED !!!; fi

#ssh -q root@$fromip "interface eoip add name=eoip-tunnel_Ensico mtu=1500 local-address=$eoipl remote-address=$eoipr tunnel-id=$TID keepalive=10,10" 2>/dev/null
#ssh -q root@$fromip "interface bridge port add interface=eoip-tunnel_Ensico bridge=bridge-Ensico"
#if ssh -q root@$fromip "interface eoip print" 2>/dev/null |grep $eoipl 1>/dev/null; then echo eoip_tunnel IP update OK!; else echo eoip_tunnel IP update FAILED !!!; fi

ssh -q root@$fromip "interface eoip set [ find name=eoip-tunnel_Ensico ] local-address=$eoipl remote-address=$eoipr tunnel-id=$TID" 2>/dev/null
if ssh -q root@$fromip "interface eoip print" 2>/dev/null |grep $eoipl 1>/dev/null; then echo eoip_tunnel IP update OK!; else echo eoip_tunnel IP update FAILED !!!; fi

# bridge-local nat update
ssh -q root@$fromip "ip firewall nat set [ find comment=lan_nat ] src-address=$net" 2>/dev/null
if ssh -q root@$fromip "ip firewall nat print value-list" 2>/dev/null|grep -w $net 1>/dev/null; then echo bridge-local NAT update OK!; else echo bridge-local NAT update FAILED !!!; fi

# syslog change
ssh -q root@$fromip "system logging set prefix=$id [/system logging find where action=syslog]" 2>/dev/null
if ssh -q root@$fromip "system logging print" 2>/dev/null | grep $id 1>/dev/null; then echo syslog change OK!; else echo syslog change FAILED !!; fi

# mangle change
ssh -q root@$fromip "ip firewall mangle set [ find comment=bridge-local-connection-out ] dst-address=$net" 2>/dev/null
if ssh -q root@$fromip "ip firewall mangle print"|grep -A 4 ";;; bridge-local-connection-out" 2>/dev/null|grep -w $net 1>/dev/null;then echo bridge-local connection-out MANGLE update OK!; else echo bridge-local-connection-out MANGLE update FAILED !!!; fi


ssh -q root@$fromip "ip firewall mangle set [ find comment=bridge-local-connection-in ] src-address=$net" 2>/dev/null
if ssh -q root@$fromip "ip firewall mangle print"|grep -A 4 ";;; bridge-local-connection-in" 2>/dev/null|grep -w $net 1>/dev/null; then echo bridge-local-connection-in MANGLE update OK!; else echo bridge-local-connection-in MANGLE update FAILED !!!; fi


ssh -q root@$fromip "ip firewall mangle set [ find comment=stream-connection-out ] dst-address=${stream}.104/29" 2>/dev/null
if ssh -q root@$fromip "ip firewall mangle print"|grep -A 4 ";;; stream-connection-out" 2>/dev/null|grep -w "${stream}.104/29" 1>/dev/null;then echo stream-connection-out MANGLE update OK!;else echo stream-connection-out MANGLE update FAILED !!!; fi

ssh -q root@$fromip "ip firewall mangle set [ find comment=stream-connection-in ] dst-address=${stream}.104/29 src-address=$stream.104/29" 2>/dev/null
if ssh -q root@$fromip "ip firewall mangle print"|grep -A 4 ";;; stream-connection-in" 2>/dev/null|grep -w "${stream}.104/29" 1>/dev/null; then echo stream-connection-in MANGLE update OK!; else echo stream-connection-in MANGLE update FAILED !!!; fi

# address list
ssh -q root@$fromip "ip firewall address-list set [ find where list=destination_ip comment=MIKROTIK_OVPN ] address=$net"
if ssh -q root@$fromip "ip firewall address-list print"|grep destination_ip|grep $net 1>/dev/null; then echo address-list destination_ip update OK!; else echo address-list destination_ip update FAILED !!!; fi

ssh -q root@$fromip "ip firewall address-list set [ find where list=destination_ip comment=Ensico_OVPN ] address=$net2"
if ssh -q root@$fromip "ip firewall address-list print"|grep destination_ip|grep $net2 1>/dev/null; then echo address-list destination_ip Ensico update OK!; else echo address-list destination_ip Ensico update FAILED !!!; fi

ssh -q root@$fromip "ip firewall address-list set [ find where list=source_ip comment=MIKROTIK_OVPN ] address=$net"
if ssh -q root@$fromip "ip firewall address-list print"|grep source_ip|grep $net 1>/dev/null; then echo address-list source_ip update OK!; else echo address-list source_ip update FAILED !!!; fi

ssh -q root@$fromip "ip dhcp-server network set [ find comment=lan ] address=$net gateway=$gw dns-server=$gw" 2>/dev/null
if ssh -q root@$fromip "ip dhcp-server network print" 2>/dev/null|grep -w $gw 1>/dev/null; then echo bridge-local DHCP-server update OK!; else echo bridge-local DHCP-server update FAILED !!!; fi

ssh -q root@$fromip "ip pool set psk-pool ranges=$pool" 2>/dev/null
if ssh -q root@$fromip "ip pool print" 2>/dev/null|grep -w $pool 1>/dev/null; then echo psk DHCP-pool update OK!; else echo psk DHCP-pool update FAILED !!!; fi

ssh -q root@$fromip "system identity set name=$id" 2>/dev/null
if ssh -q root@$fromip "system identity print" 2>/dev/null|grep -w $id 1>/dev/null; then echo ID update OK!; else echo ID update FAILED !!!; fi

ssh -q root@$fromip 'user set admin password=mk7!k0'

ls /openvpn/easy-rsa/Mikrotik/keys/|grep $id 1>/dev/null || /root/mikrotik/src $id 1>/dev/null
#openssl rsa -in /openvpn/easy-rsa/Mikrotik/keys/$id.key -out /openvpn/easy-rsa/Mikrotik/keys/$id.pem 1>/dev/null 2>&1

scp /openvpn/easy-rsa/Mikrotik/keys/$id.crt /openvpn/easy-rsa/Mikrotik/keys/$id.pem $fromip:/ 1>/dev/null 2>&1
ssh -y -q root@$fromip "certificate remove 0"
ssh -y -q root@$fromip "certificate remove 1"


cd /openvpn/easy-rsa/Mikrotik/keys/

echo Transfering $id.crt !
expect /root/mikrotik/certimport $fromip $id.crt 2>/dev/null
sleep 2
echo Transfering $id.pem !
expect /root/mikrotik/certimport $fromip $id.pem 2>/dev/null
sleep 2
echo Transfering Mikrotik_ca.crt !
expect /root/mikrotik/certimport $fromip Mikrotik_ca.crt 2>/dev/null


if [ "$pskid" == "psk223" ]; then
	ssh -y -q -f root@$fromip "interface ovpn-client set certificate=$pskid.crt_0 numbers=0"
else
	ssh -y -q -f root@$fromip "interface ovpn-client set certificate=$pskid.crt_0 numbers=0" 
fi

#ssh -q $fromip "interface ovpn-client disable numbers=0"
#sleep 2
#ssh -q $fromip "interface ovpn-client enable numbers=0"
#sleep 2

echo Waiting for $id !
while true; do ping -c 1 -i 1 $ovpnip > /dev/null && break; done
sleep 2
echo "DSL user is: $adsluser"
timeout 3 ssh -q root@$ovpnip "interface pppoe-client set user=$adsluser@htnet-dsl password=$adslpass numbers=htdsl" 2>/dev/null
sleep 1
echo Promjena zavrsena !
pkill -f "ssh -f" 1>/dev/null 2>&1
sleep 2
fi
fi
else
echo not connected
sleep 3
fi
}

#--------------------------------------------

# Submenu 2
f_subm2 () {

echo -n "ID Poslovnice? : "
read pskid
grepid=`grep $pskid /root/mikrotik/ipranges`
if [ "$grepid" == "" ]; then
echo "Invalid ID $pskid";    
sleep 3
else

# Mikrotik
id=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f1`
ip=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f2`
net=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f3`
gw=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f4`
pool=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f5`
ovpnip=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f6`

ssh -q root@$ovpnip "ip address print brief" 2>/dev/null |grep -w $ip 1>/dev/null && echo IP OK !

ssh -q root@$ovpnip "ip firewall nat print value-list" 2>/dev/null|grep -w $net 1>/dev/null && echo NAT OK !

ssh -q root@$ovpnip "ip firewall mangle print value-list" 2>/dev/null|grep -w $net 1>/dev/null && echo MANGLE OK !

ssh -q root@$ovpnip "ip dhcp-server network print" 2>/dev/null|grep -w $gw 1>/dev/null && echo DHCP-server OK !

ssh -q root@$ovpnip "ip pool print" 2>/dev/null|grep -w $pool 1>/dev/null && echo DHCP-pool OK !

ssh -q root@$ovpnip "system identity print" 2>/dev/null|grep -w $id 1>/dev/null && echo ID OK !

ssh -q root@$ovpnip "interface pppoe-client print value-list" 2>/dev/null|grep -w -A1 "user:"

ssh -q root@$ovpnip "interface ppp-client print value-list" 2>/dev/null|grep -w "pin:"

ssh -q root@$ovpnip "ip dns print" |grep -w "allow-remote-requests:"

ssh -q root$ovpnip "interface pppoe-client export file=htdsl"

ssh -q root$ovpnip "interface ppp-client export file=htgprs"

sleep 7
fi


}

### Disable Betshop
f_subm3 () {


echo -n "ID Poslovnice? : "
read pskid
if [ "$pskid" == "" ]; then
	echo "Invalid ID ";    
	sleep 3
else
	grepid=`grep $pskid /root/mikrotik/ipranges`
	if [ "$grepid" == "" ]; then
	echo "Invalid ID $pskid";    
	sleep 3
	fi
fi


	
# Mikrotik
id=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f1`
ip=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f2`
net=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f3`
gw=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f4`
pool=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f5`
ovpnip=`cat /root/mikrotik/ipranges|grep $pskid|cut -d ";" -f6`
stream=`echo $net|cut -d "." -f1,2,3`


	sudo sed -i "s/$ovpnip/X$ovpnip/g" /root/mikrotik/pskdbf/pskdb
	sleep 1
	sudo sh /root/mikrotik/pskdbf/hostupdate
	echo $id disabled
	sleep 4
}
#--------------------------------------------
#                MENU SECTION
#--------------------------------------------

# Main menu
while : # Loop forever
do
	clear
cat << !

	MAIN

	1. Add/Change Betshop
	2. Test
	3. Disable Betshop
	0. Quit

!

	echo -n " select ? : "
	read choice
	case $choice in
		1) f_subm1 ;;
		2) f_subm2 ;;
		3) f_subm3 ;;
		0) exit ;;
		*) echo "\"$choice\" is not valid "; break ;;

	esac
done

#--------------------------------------------