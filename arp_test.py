import os


# checks if the scanned IP address equals the target
def arp_request(target_ip):
    with os.popen('arp -a') as f:
        data = f.read()
    import re
    for line in re.findall('([-.0-9]+)\s+([-0-9a-f]{17})\s+(\w+)', data):
        if line[0] == target_ip:
            return line[1]
