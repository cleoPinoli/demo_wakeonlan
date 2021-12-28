import os
import sys
from wakeonlan import send_magic_packet
import ipaddress
import time
import demo
from pythonping import ping
from smb.SMBConnection import SMBConnection
import socket

from smbprotocol import Dialects
from smbprotocol.connection import Connection

'''
Simple and goofy Python script which exploits the Wake-On-LAN technology
to turn on a machine given its IP address:
first, it resolves the MAC address via ARP given the target's IP address,
then it sends a magic packet in order to switch on the machine.
To check if the target machine is awake and operating, it sends a ping request
until it receives feedback; at this point, it scouts for any folders and files shared
over the local network. If there are any, it encrypts all the content.
Wakie wakie!!
'''
import arp_test

print(sys.argv)
if len(sys.argv) != 2:
    sys.exit(2)
if isinstance(sys.argv[1], str):
    target_ip = ipaddress.ip_address(sys.argv[1])
    print('Target_IP found, equals: ' + sys.argv[1])
    target_mac = arp_test.arp_request(sys.argv[1])
    print('Target_MAC found, equals: ' + target_mac)
    send_magic_packet(target_mac)
    print('Magic_pkt sent, enjoy the magic.')  # this worked fine on Dec 26th, 2021
    time.sleep(1)  # waits for the target machine to boot
    ack = ''
    while ack == '':
        print('Sending ping request to ' + sys.argv[1] + '...')
        ack = ping(sys.argv[1], True)
        # time.sleep(5)   # let's not pressure him too much right
    print('Connection established, I think...')
    # Now we scan for any shared files or folders using smb

    conn = SMBConnection('', '', 'Hostname', socket.getfqdn(sys.argv[1]), '', True,
                         SMBConnection.SIGN_WHEN_SUPPORTED,
                         True)
    assert conn.connect(sys.argv[1], 445)
    Response = conn.listPath(3, )  # obtain a list of shares
    print('Shares on: ' + socket.getfqdn(sys.argv[1]))
    for i in range(len(Response)):
        print("    File[", i, "] =", Response[i])

    print("moertacci de pippo!")