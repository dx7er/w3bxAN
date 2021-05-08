#port scanner in python made by importing nmap module
#only scans soome specific ports

import nmap 
import sys 

target = str(sys.argv[1])
ports = [21,22,80,139,443,8080]

scan_v = nmap.PortScanner()

print("\nScanning",target,"for ports 21,22,80,139,443 and 8080...\n")

for port in ports:
    portscan = scan_v.scan(target,str(port))
    print("Port",port," is ",portscan['scan'][list(portscan['scan'])[0]]['tcp'][port]['state']) 

print("\nHost",target," is ",portscan['scan'][list(portscan['scan'])[0]]['status']['state'])
