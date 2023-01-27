import sys
import socket
import random
import re

switches = ["-t", "-r", "-p", "-mx", "-ns"]
switches_values_dict = {"-t": 5,
                    "-r": 3,
                    "-p": 53,
                    "-mx": False,
                    "-ns": False,
                    }
address_set = False
server_IP_address = "",
domain_name = ""

for i in range(0, len(sys.argv)):

    if sys.argv[i] in switches:

        if (sys.argv[i] == "-mx" or sys.argv[i] == "-ns"):
            if not address_set:
                switches_values_dict[sys.argv[i]] = True
                address_set = True
            continue
        
        i_temp = i + 1
        key = sys.argv[i]
        value = sys.argv[i_temp]
        switches_values_dict[key] = value

    else:
        if "@" in sys.argv[i]:
            server_IP_address = sys.argv[i].strip("@")
        else:
            domain_name = sys.argv[i]


# DNS Questions Preparation
if switches_values_dict["-mx"]: q_type = "000f"
elif switches_values_dict["-ns"]: q_type = "0002"
else: q_type = "0001"

q_class = "0001" # Default
q_name = ""

## Parsing of the qname
domain_name_sliced = domain_name.split(".")
for slice in domain_name_sliced:
    length = len(slice)
    slice_length = format(hex((length))).lstrip("0x")
    if len(slice_length) == 1: 
        slice_length = "0" + slice_length

    q_name += slice_length
    for char in slice:
        char_hex_value = format(hex(ord(char))).lstrip("0x")
        q_name += char_hex_value

q_name += "00"
# print("Qname", q_name)

## DNS Questions parsed
dns_question = q_name + q_type + q_class
# print("Question", dns_question)

# Header Preparation
dns_header = ""

id = hex(random.getrandbits(16)).strip("0x").zfill(4)
# print(id)
flags = '0100'
qdcount = '0001' 
ancount = '0000' 
nscount = '0000' 
arcount = '0000' 

dns_header = id + flags + qdcount + ancount + nscount + arcount
# print("Header", dns_header)

# DNS Packet (header + question)
dns_packet =  dns_header + dns_question
print("DNS Packet in HEX", dns_packet)
dns_packet_bytes = bytes.fromhex(dns_packet)
print("DNS Packet in BYTES", dns_packet_bytes)

# UDP Client 
server_Port = switches_values_dict["-p"]
bytes_to_send = dns_packet_bytes
server_Address_Port = (server_IP_address,server_Port)
# print(server_Address_Port)

udp_carl = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
bufferSize = 1024

## Send to server using created UDP socket
udp_carl.sendto(bytes_to_send, server_Address_Port)
msgFromServer = udp_carl.recvfrom(bufferSize)
msg = msgFromServer[0]
msg_hex = msg.hex()
msg_bin = format(int(msg_hex, 16), '0>42b')
# print(msg)
print("Server Message", msg)
print("Server Message in Binary", msg_bin)
print("Server Message in Hex", msg_hex)

# Parsing the response packet

## Initialising dict to keep track of header values for OUTPUT
head_response_flags_keys = ["ID", "QR", "OPCODE", "AA", "TC", "RD", "RA", "Z", 
                      "RCODE", "QDCOUNT", "ANCOUNT", "NSCOUNT", "ARCOUNT"]
initial_values = [""]*len(head_response_flags_keys)
header_response_flags_dict = dict(zip(head_response_flags_keys, initial_values))

## Decoding the header response
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
print("flags values", header_response_flags_dict)

## Sectioning of the server message for the answer section only
answer_hex = msg_hex[len(dns_packet):]
print("Server Answer in Hex", answer_hex)
## Transforming to binary rep.
answer_bin = format(int(answer_hex, 16), '0>42b')
print("Server Answer in Binary", answer_bin)
answer_bin_rows = re.findall('.'*16, answer_bin)
print(answer_bin_rows)

if answer_bin_rows[0][:2] == '11':
    index = int(answer_bin_rows[0][2:], 2) * 2
    print(index) # this number is which ith row to check for the name. This is an octet, for hex we * 2.
    # Retrieve the domain name of response
    r_name_hex = msg_hex[index:][:len(q_name)]
    r_name_hex_list = re.findall('..', r_name_hex)
    print(r_name_hex_list)
    segment_hex = ""
    r_name = ""
    i = 0
    for _ in r_name_hex_list:
        if _ == '00':
            break
        check = int(_, 16)
        if  not chr(check).isalpha() and not chr(check).isdigit():
            print(f"start index: {i+1} end index: {i+1+check}")
            print(r_name_hex_list[i+1:i+1+check])
            segment_hex = "".join(r_name_hex_list[i+1:i+1+check])
            segment_str = bytearray.fromhex(segment_hex).decode(encoding="ASCII") + "."
            r_name += segment_str
            print("segment hex", segment_hex) 
            print("segment str", segment_str) 
            i += 1 + check
            
    r_name = r_name[:-1]
    print(r_name)



    # print(bytearray.fromhex(segment_hex).decode(encoding="ASCII")) 

    # print(r_name_hex)
    # target = "00"
    # temp = r_name.index(target)
    # response_name_segment = r_name[:temp]
    # print("Segment", response_name_segment)
    # response_name_hex = "".join(response_name_segment)
    # print(response_name_hex)
    # print(bytearray.fromhex(response_name_hex).decode(encoding="ASCII")) 
    


# offset = len(dns_packet)
# print("dns packet", dns_packet)
# print(offset)
# answer_bin = msg_bin[offset:]
# answer_bin_rows = re.findall('.'*16, answer_bin)
# for i in range(len(answer_bin)):
    
# print(answer_bin_rows)
# print(hex(int(msg_bin[len(dns_packet) * 4:], 2)))
    




# answer_idx = len(dns_packet)
# answer_rows = re.findall('.'*4, msg_hex[answer_idx:]) # Include answer, authoritative, additional sections. Represents a full row of 16 bits.
# answer_half_rows = re.findall('.'*2, msg_hex)  # Each element of this list is a byte and represents half of a row

# print("Answers rows", answer_rows)
# print("Answers half rows", answer_half_rows)

# # Find the offset 
# print("Question", dns_question)
# for row in answer_rows:
#     if bin(int(row[0], 16)).lstrip("0b")[:2] == '11': #row[0] == 'c':  # This is the name part
#         print("First char of the row to check for compression", row[0])
#         offset = int(row[1:], 16) # The offset is in octets. 
#         print("Offset", offset)
#         answer_offsetted = answer_half_rows[offset:]
#         print("Response starting at", offset, answer_offsetted)
#         target = "00"
#         temp = answer_offsetted.index(target)
#         response_name_segment = answer_offsetted[:temp]
#         print("Segment", response_name_segment)
#         response_name_hex = "".join(response_name_segment)
#         print(response_name_hex)
#         print(bytearray.fromhex(response_name_hex).decode()) 

# answer_rows[]
# answers = msg_hex[answer_idx:]
# print(answers)

# Output behavior
## Example:
## DnsClient sending request for [name] 
## Server: [server IP address]
## Request type: [A | MX | NS]
## Response received after [time] seconds ([num-retries] retries)

## ***Answer Section ([num-answers] records)***                               if Answer section contains records
## IP <tab> [ip address] <tab> [seconds can cache] <tab> [auth | nonauth      if response contains type A records

## CNAME <tab> [alias] <tab> [seconds can cache] <tab> [auth | nonauth]         if records in answer section is of type CNAME,MX,NS
## MX <tab> [alias] <tab> [pref] <tab> [seconds can cache] <tab> [auth | 
## nonauth] NS <tab> [alias] <tab> [seconds can cache] <tab> [auth | nonauth]

## ***Additional Section ([num-additional] records)***                          if Addition section contains records
## NOTFOUND                                                                     if no records are found
## ERROR <tab> [description of error]                                           if any errors happen