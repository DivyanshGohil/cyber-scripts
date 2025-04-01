from scapy.all import *

ports = [25,80,53,443,445,8080,8443]

def SynScan (host):
    ans,unans = sr(IP(dst=host)/TCP(dport=ports,flags="S"),timeout=2,verbose=0)
    print("Open ports at %s:" %host)
    for (s,r,) in ans:
        if s.haslayer(TCP) and r.haslayer(TCP):
            if s[TCP].dport == r[TCP].sport:
                print(s[TCP].dport)

def DNSScan(host):
    ans,unans = sr(IP(dst=host)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="google.com")),timeout=2,verbose=0)
    if ans:
        print("DNS server at %s" %host)
    elif unans:
        print("No DNS server at %s" %host)
        
host="208.67.222.222"

SynScan(host)
DNSScan(host)
