
from scapy.all import *
from prettytable import PrettyTable
from collections import Counter

# Read the packets from file
packets = rdpcap('capture.pcap')

# List to hold srcIPs 
srcIP=[]

# Read each packet and append to the srcIP list. 
for pkt in packets:
    if IP in pkt:
        try:
            srcIP.append(pkt[IP].src)
        except:
           pass

# Crreate an empty list to hold the count of ips
cnt = Counter()

# Create a list of IPs and how many times they appeared
for ip in srcIP:
    cnt[ip] += 1

# Create header
table = PrettyTable(["IP", "Count"])

# Add records to table
for ip, count in cnt.most_common():
    table.add_row([ip, count])

print(table)
