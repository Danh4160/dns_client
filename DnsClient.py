import sys
import socket
import random
import binascii 
import re

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

# Header
dns_header = ""

id = hex(random.getrandbits(16)).strip("0x").zfill(4)
print(id)
flags = '0100'
qdcount = '0001' 
ancount = '0000' 
nscount = '0000' 
arcount = '0000' 

dns_header = id + flags + qdcount + ancount + nscount + arcount
print("Header", dns_header)

# DNS Packet (header + question)
dns_packet =  dns_header + dns_question
print("DNS Packet in HEX", dns_packet)
dns_packet_bytes = bytes.fromhex(dns_packet)
print("DNS Packet in BYTES", dns_packet_bytes)

# UDP Client 
server_Port = flags_values_dict["-p"]
bytes_to_send = dns_packet_bytes
server_Address_Port = (server_IP_address,server_Port)
print(server_Address_Port)

udp_carl = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
bufferSize = 1024

# Send to server using created UDP socket
udp_carl.sendto(bytes_to_send, server_Address_Port)
msgFromServer = udp_carl.recvfrom(bufferSize)
msg = msgFromServer[0]
msg_hex = msg.hex()
print(msg)
print(msg_hex)

# Parsing the response packet

## Initialising dict to keep track of header values for OUTPUT
head_response_flags_keys = ["ID", "QR", "OPCODE", "AA", "TC", "RD", "RA", "Z", 
                      "RCODE", "QDCOUNT", "ANCOUNT", "NSCOUNT", "ARCOUNT"]
initial_values = [""]*len(head_response_flags_keys)
flags_size = [1,4,1,1,1,1,3,4]

header_response_flags_dict = dict(zip(head_response_flags_keys, initial_values))

# Decoding the header response
header_response_rows = re.findall('.'*4, msg_hex[:24])
flags_values = bin(int(header_response_rows[1], 16)).lstrip("0b")
    
header_response_flags_dict["ID"] = header_response_rows[0]

header_response_flags_dict["QR"] = flags_values[0]
header_response_flags_dict["OPCODE"] = flags_values[1:5]
header_response_flags_dict["AA"] = flags_values[5]
header_response_flags_dict["TC"] = flags_values[6]
header_response_flags_dict["RD"] = flags_values[7]
header_response_flags_dict["RA"] = flags_values[8]
header_response_flags_dict["Z"] = flags_values[9:12]

header_response_flags_dict["RCODE"] = flags_values[12:16]
header_response_flags_dict["QDCOUNT"] = header_response_rows[2]
header_response_flags_dict["ANCOUNT"] = header_response_rows[3]
header_response_flags_dict["NSCOUNT"] = header_response_rows[4]
header_response_flags_dict["ARCOUNT"] = header_response_rows[5]

print(header_response_flags_dict)

answer_idx = len(dns_packet)
print(answer_idx)
answer_rows = re.findall('.'*4, msg_hex[answer_idx:])
answer_rows_2 = re.findall('.'*2, msg_hex)

print(answer_rows)
print(answer_rows_2)

# Find the offset 
for row in answer_rows:
    if row[0] == 'c':
        offset = int(row[1:], 16)

