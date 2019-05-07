#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May  7 12:03:42 2019

@author: anthony
"""
from scapy.all import *

pcap_file = "images5.pcap"
packets = rdpcap(pcap_file)

#packets.summary() 
def countpackets(pcap_file, type ):
    print("Total Number of", type, "packets")
    tot_packets = len(packets[type])
    return tot_packets

countpackets(pcap_file, type = TCP)
#print("Total number of packets", packets[type])

