import pyshark

FILE = 'older_trick.pcap'
pcap = pyshark.FileCapture(FILE)


#print(pcap[1811].icmp)

answer = b''
for packet in pcap:
	try:
		relevant = packet.icmp.data
		if packet.ip.src == '192.168.1.7':
		
            #print(bytes.fromhex(relevant[48:80]))
			answer += bytes.fromhex(relevant[48:80])
			#break
	except Exception as e:
		pass
print(len(answer))

f = open("my_output.zip", "wb")
f.write(answer)
