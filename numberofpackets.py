#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May  7 12:03:42 2019

@author: anthony
"""
#GOALS
#List of Protocols & Ports src -> dst 
#Deliminated into columns 


#Imports 
import os
import cv2
from scapy.all import *
from pathlib import Path

# Read in files
#-------OLD GET FILE, NO GUI .-. -----#
##Uncomment for testing 
data_folder = Path("data/")
pcap_file = data_folder / "images5.pcap" 
pcap_file = ("data/images5.pcap")

#------Protocol Types into Array & Read in pcap file
#Could just set it to rootfilename but who needs clean code
#packets = rdpcap(root.filename)

ourpcap = rdpcap(pcap_file)
print(ourpcap.listname, "Opened...")

# =============================================================================
def counters(file):
    print("***", file.listname.upper, "Breakdown***\n")
    print('Total Number of packets:', len(file)) 
    print('Protocol Breakdown:', file)

# =============================================================================
# Top 5 Sessions
# =============================================================================
def top5(file):
    print("Top 5 Sessions")             
    s = file.sessions() #store the sessions data into s 
    for k in sorted(s, key=lambda k: len(s[k]), reverse=True)[:5]:
        print("Packet count:",len(s[k]),'Session =====>', k)

# =============================================================================
# Question --- 4.1.5 Activy Sniff. Report Same Stats as above...
# =============================================================================
def sniffinf():
    print("\nSniffing...")
    pkts = sniff(iface='eth0', timeout=10, count=1000)
    print("Done!")
    wrpcap('temp.pcap',pkts)
    global temp
    temp = rdpcap('temp.pcap')
    return temp




#Call all the functions. Should put into class
counters(ourpcap)
top5(ourpcap)
sniffinf()
counters(temp)      #call function to preform functions 1-4
top5(temp)          #function to summarize packets



# =============================================================================
# =============================================================================
# # 4.2 Deep Packet Inspection 
# =============================================================================
# =============================================================================


# =============================================================================
# QUESTION --- 4.2.1 Iterate though each sessions and packet using loops
# =============================================================================
#for key,value in sessions.items() print key + print value
s = ourpcap.sessions()
for k,v in s.items():
    for p in v: #For p in values print time + key, ITERATE THROUGH THE PACKET OBJECTS 
        layer_type = type(p[IP].payload)
        print("packet type:", layer_type.__name__,"\n", k)





# =============================================================================
# IMAGE RECOGNITION
# =============================================================================
##%%
#
#pictures_directory = "/home/cifauser/Documents/Programming/pcap_scrapping/pictures"
#faces_directory = "/home/cifauser/Documents/Programming/pcap_scrapping/faces"
#
#
#
#def get_http_headers(http_payload):
#    print (http_payload)
#    try:
#        #split the hearders off if it is HTTP traffic
#        headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
#        
#        #break out the headers
#        headers = dict(re.findall(r"('?P<name>.*?'): ('?P<value>.*?')\r\n", headers_raw))
#        dir(headers)
#    except:
#        return None
#    
#    if "Content-Type" not in headers:
#        return None
#    print(headers)
#    return headers
#
#def extract_image(headers,http_payload):
#    image = None
#    image_type = None
#    
#    try:
#        if "image" in headers['Content-Type']:
#            
#            #grab the image type and image body
#            image_type = headers['Content-Type'].split("/")[1]
#            
#            image = http_payload[http_payload.index("\r\n\r\n")+4:]
#            
#            #if we detect compression decompress the image
#            try:
#                if "Content-Encoding" in headers.keys():
#                    if headers['Content-Encoding'] == "gzip":
#                        image = zlib.decompress(image, 16+zlib.MAX_WBITS)
#                    elif headers['Content-Encoding'] == "deflate":
#                        image = zlib.decompress(image)
#            except:
#                pass
#    except:
#        print("ERROR IN DETECTING IMAGE")
#        print("------------------------")
#        return None,None
#    
#    return image,image_type
#
#
##Facial Detection Code
#def face_detect(path,file_name):
#    
#    img = cv2.imread(path)
#    cascade = cv2.CascadeClassifier("haarcascade_frontalface_alt.xml")
#    rects = cascade.detectMultiScale(img, 1.3, 4, cv2.cv.CV_HAAR_SCALE_IMAGE, (20,20))
#    
#    if len(rects) == 0:
#        return False
#    rects[:, 2:] += rects[:, :2]
#    
##highlights the faces in teh image
#    for x1,y1,x2,y2 in rects:
#        cv2.rectangle(img,(x1,y1),(x2,y2),(127,255,0),2)
#        cv2.imwrite("%s/%s-%s" % (faces_directory,pcap_file,file_name),img)
#    
#    return True
#def http_assembler(pcap_file):
#    carved_images = 0
#    faces_detected = 0
#        
#    a = rdpcap(pcap_file)
#        
#    sessions = a.sessions()
#        
#    for session in sessions:
#        http_payload = ""
#        for packet in sessions[session]:
#                
#            try: 
#                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
#                    
#                    #reassemble the stream
#                    http_payload += str(packet[TCP].payload)
#                    
#            except:
#                pass
#        headers = get_http_headers(http_payload)
#                
#        if headers is None:
#            continue
#                
#        image,image_type = extract_image(headers,http_payload)
#        if image is not None and image_type is not None:
#            #store the image
#            file_name = "%s-pic_carver_%d.%s" % (pcap_file, carved_images,image_type)
#            fd = open("%s/%s" % (pictures_directory,file_name), "wb")
#            fd.write(image)
#            fd.close()
#                
#            carved_images += 1
#                
#            #now attempt face detection
#            try:
#                result = face_detect("%s/%s" % (pictures_directory,file_name),file_name)
#                if result is True:
#                    faces_detected += 1
#            except:
#                pass
#    
#    return carved_images, faces_detected 
#
#carved_images, faces_detected = http_assembler(pcap_file)
#
#print ("Extracted: %d images" % carved_images)
#print ("Detected: %d faces" % faces_detected)
#
#http_assembler(pcap_file)
#


#%%





# =============================================================================
#         MAYBE HELPFUL
# =============================================================================
#p.mysummary
#print("Options: ls(packet) -- list packets")


# =============================================================================
# Helpful Code Chunks
# =============================================================================
#Take type argument, return total packets found in PCAP matching type
#protos = [TCP, UDP, DHCP, DNS, SCTP, NTP]
#def countpackets(type):
#    tot_packets = (len(ourpcap[type]))
#    return tot_packets
# =======================================

#Attempt at putting into class... 
#class doitall(file):
#    def sniffinf():
#        print("Sniffing...")
#        pkts = sniff(iface='eth0', timeout=10, count=1000)
#        print("Done!")
#        wrpcap('temp.pcap',pkts)
#        temp = rdpcap('temp.pcap')
#        counters(file)
#        
#    def top5(self, file):
#        print("Top 5 Sessions")             
#        s = file.sessions() #store the sessions data into s 
#        for k in sorted(s, key=lambda k: len(s[k]), reverse=True)[:5]:
#            print("Packet count:",len(s[k]),'Session =====>', k)    
#    def counters(self, file):
#        print("***", file.listname.upper, "Breakdown***\n")
#        print('Total Number of packets:', len(file)) 
#        print('Protocol Breakdown:', file)



#for r in ourpcap.res:
#    for p in outt:
#    print(ourpcap._elt2pkt(r).haslayer(p))
#    ourpcap.make_table(lambda x:(p[IP].dst, p[TCP].dport, p[TCP].sprintf("%flags%")))








#s
##for key,value in sessions.items() print key + print value
#for k,v in s.items():
#    print (v)
#    print (k)
#    v.haslayer
##    print(v.summary())
##    print(v.listname)
##    print(v.listna)
#    for p in v: #For p in values print time + key, ITERATE THROUGH THE PACKET OBJECTS 
#        v.make_table(lambda p:(p[IP].dst, p[UDP].dport, p[UDP].sprintf("%flags%"))) 
#        type(p)
#        p.haslayer(Raw)
#        for proto in protos:
#            print(p("%s" + proto))
#            p(proto)
#
#       p.summary(proto)
#        p.fieldtype[]
#        p.display()
##        
##        print(p.time, k)
##        p.packetfields
##        print(p.fieldtype)
##        p[UDP].dport

        
        

