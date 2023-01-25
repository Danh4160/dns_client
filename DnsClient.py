import sys
import socket
import random
import binascii 

flags = ["-t", "-r", "-p", "-mx", "-ns"]
flags_values_dict = {"-t": 5,
                    "-r": 3,
                    "-p": 53,
                    "-mx": False,
                    "-ns": False,
                    }
address_set = False
server_IP_address = "",
domain_name = ""

for i in range(0, len(sys.argv)):

    if sys.argv[i] in flags:

        if (sys.argv[i] == "-mx" or sys.argv[i] == "-ns"):
            if not address_set:
                flags_values_dict[sys.argv[i]] = True
                address_set = True
            continue
        
        i_temp = i + 1
        key = sys.argv[i]
        value = sys.argv[i_temp]
        flags_values_dict[key] = value

    else:
        if "@" in sys.argv[i]:
            server_IP_address = sys.argv[i].strip("@")
        else:
            domain_name = sys.argv[i]


# DNS Questions Preparation
if flags_values_dict["-mx"]: q_type = "000f"
elif flags_values_dict["-ns"]: q_type = "0002"
else: q_type = "0001"

q_class = "0001"
q_name = ""

domain_name_sliced = domain_name.split(".")
for slice in domain_name_sliced:
    length = len(slice)
    slice_length = format(hex((length))).strip("0x")
    if len(slice_length) == 1: 
        slice_length = "0" + slice_length

    q_name += slice_length
    for char in slice:
        char_hex_value = format(hex(ord(char))).strip("0x")
        q_name += char_hex_value

q_name += "00"
print("Qname", q_name)

# DNS Questions parsed
dns_question = q_name + q_type + q_class
print("Question", dns_question)

#Header
dns_header = ""

id = str(random.getrandbits(15))
flags = '0100'
# qr = '0'
# opcode= '0000'
# aa = '0'
# tc = '0'
# rd = '1'
# ra = '0'
# z = '000'
# rcode = '0000'

# Cumulation of flags
# flags = qr + opcode + aa + tc + rd + ra + z + rcode

##Each of these are 16 bit
qdcount = '0001' ##should be 1
ancount = '0000' ##values dependent on answer
nscount = '0000' ##values dependent on answer however program can ignore response entries in this section
arcount = '0000' ##values dependent on answer

dns_header = id + flags + qdcount + ancount + nscount + arcount
print("Header", dns_header)

# DNS Packet (header + question)
dns_packet =  dns_header + dns_question
print("DNS Packet in HEX", dns_packet)
dns_packet_bytes = bytes.fromhex(dns_packet)
# dns_packet_bytes = binascii.unhexlify(dns_packet)
print("DNS Packet in BYTES", dns_packet_bytes)


# # UDP Client 
server_Port = flags_values_dict["-p"]
bytes_to_send = dns_packet_bytes
server_Address_Port = (server_IP_address,server_Port)
print(server_Address_Port)

udp_carl = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
bufferSize = 1024

# Send to server using created UDP socket
udp_carl.sendto(bytes_to_send, server_Address_Port)
msgFromServer = udp_carl.recvfrom(bufferSize)
# print(msgFromServer[0])
msg = "Message from Server {}".format(msgFromServer[0])
print(msg)