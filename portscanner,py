#simple port scanner
#basic scanner, check for open ports
import socket
from IPy import IP


def scan(target,port_num):
    converted_ip=checkip(target)
    print('\n'+ '[-_0 Scanning Target] '+ str(target))
    for port in range(1,port_num):
        scan_port(converted_ip,port)
  
  
def get_banner(s):
    return s.recv(1024)
  
def checkip(ipaddress):
    try:
        IP(ipaddress)    
        return ipaddress
    except ValueError:
        return socket.gethostbyname(ipaddress)
    
    
def scan_port(ipaddress,port):
    try:
        sock=socket.socket()
        sock.settimeout(1)
        sock.connect((ipaddress, port))
        try:
            banner=get_banner(sock)
            print('[+] Open Port '+ str(port)+' : '+str(banner.decode().strip('\n')))
        except:
            print('[+] Open Port '+ str(port))
    except:
        pass
        
targets=input('[+] Enter Target/s to Scan(split multiple targets with ,): ')
port_num=int(input('[+] Enter Number of Ports You want To scan: '))

if ',' in targets:
    for ip_add in targets.split(','):
        scan(ip_add.strip(' '),port_num)
else:
    scan(targets,port_num)
