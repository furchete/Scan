#!/usr/bin/python3

import nmap
print()
print(" ________       ________      ________      ________ ")
print("|\   ____\     |\   ____\    |\   __  \    |\   ___  \ ")
print("\ \  \___|_    \ \  \___|    \ \  \|\  \   \ \  \\ \  \ ")
print(" \ \_____  \    \ \  \        \ \   __  \   \ \  \\ \  \ ")
print("  \ \_____  \    \ \  \        \ \   __  \   \ \  \\ \  \   ")
print("   \|____|\  \    \ \  \____    \ \  \ \  \   \ \  \\ \  \  ")
print("     ____\_\  \    \ \_______\   \ \__\ \__\   \ \__\\ \__\ ")
print("    |\_________\    \|_______|    \|__|\|__|    \|__| \|__| ")
print("    \|_________|                                            ")


print("[Info] Tool for scanning open ports on an address IP")
print(" ||| Written in Python and uses Nmap |||")
print(" ||| Not created by me rights reserved to Contando Bits. created for cybersecurity practice. |||")

host = input("[*] Introduce la IP objetivo: ")
nm = nmap.PortScanner()
open_ports = "-p "
count = 0
results = nm.scan(hosts=host, arguments="-sT -n -Pn -T4")
#print (results)
print("Host : %s" % host)
print("State : %s" % nm[host].state())
for proto in nm[host].all_protocols():
    print('Protocol : %s' % proto)
    lport = nm[host][proto].keys()
    sorted(lport)
    for port in lport:
        print('port : %s\tstate: %s' % (port, nm[host][proto][port]['state']))
        if count == 0:
            open_ports = open_ports+" "+str(port)
            count = 1
        else:
            open_ports = open_ports+","+str(port)


print("Open Ports: "+open_ports+" "+str(host))
