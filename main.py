import sys
from wakeonlan import send_magic_packet
import ipaddress

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
    print('Magic_pkt sent, enjoy the magic.')


