#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 10 19:43:41 2019

@author: 
@author: Code from ronaldeddings
"""
#GOALS
#List of Protocols & Ports src -> dst 
#Deliminated into columns 


# =============================================================================
# Imports 
# =============================================================================
import os
from scapy.all import *
from pathlib import Path
import pandas as pd
import binascii # Binary to Ascii 
from progressbar import ProgressBar
import tkinter as tk
from tkinter import filedialog
from tkinter import *

# =============================================================================
# Read in data 
# =============================================================================

#file_name = input('enter file name:')
#pcap_file = open("data/" + file_name)

#data_folder = Path("data/")
#pcap_file = data_folder / "wrccdc2012.pcap" 
#pcap_file = ("data/wrccdc2012.pcap")
pbar = ProgressBar()

root = Tk()
root.filename =  filedialog.askopenfilename(initialdir = "/",title = "Select file",filetypes = (("pcap","*.pcap"),("all files","*.*")))
pcap_file = root.filename
root.destroy()

# =============================================================================
# Protocol Types into Array & Read in pcap file
# =============================================================================
#Could just set it to rootfilename but who needs clean code
#packets = rdpcap(root.filename)
ourpcap = rdpcap(pcap_file)
print(ourpcap.listname, "Opened")



# =============================================================================
# Convert PCAP to DataFrame
# SOURCE: https://github.com/ronaldeddings/Packet-Analytics/blob/master/Packet-Analytics.ipynb
# I am in forever debt to @ronaldeddings for this 
# =============================================================================

# Collect field names from IP/TCP/UDP (These will be columns in DF)
ip_fields = [field.name for field in IP().fields_desc]
tcp_fields = [field.name for field in TCP().fields_desc]
udp_fields = [field.name for field in UDP().fields_desc]

dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload','payload_raw','payload_hex']

# Create blank DataFrame
df = pd.DataFrame(columns=dataframe_fields)
for packet in pbar(ourpcap[IP]):
    # Field array for each row of DataFrame
    field_values = []
    # Add all IP fields to dataframe
    for field in ip_fields:
        if field == 'options':
            # Retrieving number of options defined in IP Header
            field_values.append(len(packet[IP].fields[field]))
        else:
            field_values.append(packet[IP].fields[field])
    
    field_values.append(packet.time)
    
    layer_type = type(packet[IP].payload)
    for field in tcp_fields:
        try:
            if field == 'options':
                field_values.append(len(packet[layer_type].fields[field]))
            else:
                field_values.append(packet[layer_type].fields[field])
        except:
            field_values.append(None)
    
    # Append payload
    field_values.append(len(packet[layer_type].payload))
    field_values.append(packet[layer_type].payload.original)
    field_values.append(binascii.hexlify(packet[layer_type].payload.original))
    # Add row to DF
    df_append = pd.DataFrame([field_values], columns=dataframe_fields)
    df = pd.concat([df, df_append], axis=0)

# Reset Index
df = df.reset_index()
# Drop old index column
df = df.drop(columns="index")

print(df.shape)




# =============================================================================
# Sessions 
# =============================================================================
#s = ourpcap.sessions()
#s
#for k,v in s.items():
#    v.summary()
#    for pkt in v:
#        pkt.show()







# =============================================================================
# Read in raw packets 
# =============================================================================
#itt = RawPcapReader(pcap_file)
#for (pkt_data, pkt_metadata,) in itt:
#    len(pkt_data)
#    ether_pkt = Ether(pkt_data)#.fields)
#    ether_pkt.summary()
#    len(pkt_metadata)
#    print(pkt_metadata)
#print(itt)
#len(ourpcap)
