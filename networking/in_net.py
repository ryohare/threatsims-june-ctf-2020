import socket,struct
import ipaddress

def addressInNetwork(ip,net):
   "Is an address in a network"
   ipaddr = struct.unpack('L',socket.inet_aton(ip))[0]
   netaddr,bits = net.split('/')
   netmask = struct.unpack('L',socket.inet_aton(netaddr))[0] & ((2L<<int(bits)-1) - 1)
   return ipaddr & netmask == netmask


with open('ipaddress.txt', 'r') as f:
    pairs = f.readlines()
for p in pairs:
    print(p.strip())
    parts = p.split(',')
    parts[1]=parts[1].strip()
    print("IP: {}".format(parts[0]))
    print("Net: {}".format(parts[1]))

    if ipaddress.ip_address( unicode(parts[0], "utf-8") ) in ipaddress.ip_network( unicode(parts[1], "utf-8") ):
        print("in net: {} in {}".format(parts[0],parts[1]))
