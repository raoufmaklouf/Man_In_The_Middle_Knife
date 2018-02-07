import os
import sys

def deb():
   os.system('sudo apt-get update')
   os.system('sudo apt-get install scapy')
   os.system('sudo apt-get install python-pip')
   os.system('sudo pip install subprocess')
   os.system('sudo pip install threading')
   os.system('sudo pip install signal')
   os.system('sudo apt-get install wireshark')
   os.system('sudo apt-get install nmap ')
def rh():
    os.system('yum update')
    os.system('sudo yum install scapy')
    os.system('sudo yum install python-pip')
    os.system('sudo yum install subprocess')
    os.system('sudo yum install threading')
    os.system('sudo yum install signal')
    os.system('sudo yum install wireshark')
    os.system('sudo yum install nmap ')
print('if your os debien enter [1]\n')
print('if your os redhat enter [2]\n')
ch=int(raw_input('os >:'))
if ch ==1:
    deb()
elif ch == 2:
    rh()
else:
   print ('read README.txt you have wrong')
   sys.exit()

