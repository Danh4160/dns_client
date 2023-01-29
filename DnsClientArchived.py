import sys
import socket
import random
import re
import time

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

## Send to server using created UDP 
start = time.time()
udp_carl.sendto(bytes_to_send, server_Address_Port)
msgFromServer = udp_carl.recvfrom(bufferSize)
end = time.time()

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



# compression = False
# read_compression_bits_done = False
# compression_counter = 0
# offset_bin = ""
# for bit in answer_bin:

#     if compression and not read_compression_bits_done:
#         offset_bin += bit
    
#     if bit == '1' and not compression:
#         compression_counter += 1
#         break
    
#     if compression_counter == 2 and  not compression:
#         # There is compression to do
#         compression_counter = 0
#         compression = True

#     if compression and read_compression_bits_done:



def retrieve_name(l, idx, r_name):
    print(f"l: {l} idx: {idx} r_name: {r_name}")
    while idx < len(l):
        element = l[idx]
        if element == '00':
            print("breaking")
            print("r_name", r_name)
            return r_name
        elif element[:1] == 'c':
            index = element + l[idx + 1]
            index_bin = format(int(index, 16), '0>16b')
            index = int(index_bin[2:], 2) * 2
            print("index", index)
            return retrieve_name(re.findall("..", msg_hex[index:]), 0, r_name)

        else:
            check = int(element, 16)
            if check < 32:
                print("check", check)
                print(f"start index: {idx+1} end index: {idx+1+check}")
                print(r_name_hex_list[idx+1:idx+1+check])
                segment_hex = "".join(l[idx+1:idx+1+check])
                segment_str = bytearray.fromhex(segment_hex).decode(encoding="ASCII") + "."
                r_name += segment_str
                print("r_name in check", r_name)
                print("segment hex", segment_hex) 
                print("segment str", segment_str) 
                idx += 1 + check
      
    return r_name

r_name_list = []
j = 0
while j < len(answer_bin_rows):
    print("J",j)
    # Retrieve domain main of a record
    if answer_bin_rows[j][:2] == '11':
        index = int(answer_bin_rows[j][2:], 2) * 2
        print("DAN INDEX",index) # this number is which ith row to check for the name. This is an octet, for hex we * 2.
        # Retrieve the domain name of response
        r_name_hex = msg_hex[index:]#[:len(q_name)]
        r_name_hex_list = re.findall('..', r_name_hex)
        print("r_name_hex_list", r_name_hex_list)
        segment_hex = ""
        r_name = ""
        
        i = 0
        r_name_list.append(retrieve_name(r_name_hex_list, i, r_name))


        # while i < len(r_name_hex_list):
        # # for i in range(len(r_name_hex_list)):
        #     print("i", i)
        #     element = r_name_hex_list[i]
        #     print("current element", element)
        #     if element[:1] == "c":
        #         index = element + r_name_hex_list[i + 1]
        #         print("index", index)
        #         print("in c")
        #         index_bin = format(int(index, 16), '0>16b')
        #         print("index_bin", index_bin)
        #         index = int(index_bin[2:], 2) * 2
        #         print("index value", index)
        #         i = index

        #     elif element == '00':
        #         print("in 00")
        #         break
        #     else:
        #         check = int(element, 16)
        #         if check < 32:
        #         # if not chr(check).isalpha() and not chr(check).isdigit():
        #             print("in if")
        #             # if el[:1] == 'c': # pointer
        #             #     # index = int(answer_bin_rows[j][2:], 2) * 2
        #             #     print("index when sequence of label ends with pointer", index)

        #             print("check", check)
        #             print(f"start index: {i+1} end index: {i+1+check}")
        #             print(r_name_hex_list[i+1:i+1+check])
        #             segment_hex = "".join(r_name_hex_list[i+1:i+1+check])
        #             segment_str = bytearray.fromhex(segment_hex).decode(encoding="ASCII") + "."
        #             r_name += segment_str
        #             print("segment hex", segment_hex) 
        #             print("segment str", segment_str) 
        #             i += 1 + check
                
        # r_name = r_name[:-1]
        # print(r_name)

    print("j", j)
    print(answer_bin_rows)
    typee = answer_bin_rows[j + 1] # in string bit
    classe = answer_bin_rows[j + 2] # in string bit
    ttl = answer_bin_rows[j + 3] + answer_bin_rows[j + 4] # in string bit
    rdlength = answer_bin_rows[j + 5] # in string bit
    print("length of rdlength", len(rdlength))
    rdata_offset = 96 # in bits

    print(f"type '{typee}' \nclass '{classe}' \nttl '{ttl}' \nrdlength '{rdlength}'")

    r_type = hex(int(typee, 2))
    r_classe = hex(int(classe, 2))
    r_ttl = hex(int(ttl, 2))
    r_rdlength = hex(int(rdlength, 2))

    rdlength_bin_size = int(rdlength, 2) * 8 #The number of bits that RData takes
    print("rdlength_bin_size", rdlength_bin_size)
    # Depends on type value
    type_value = r_type.lstrip("0x").zfill(4)
    print("type_value", type_value)
    r_data = ""
    if type_value == "0001":  # Type A
        # IP address represented using 4 octets = 32 bits
        next_record_idx = (rdata_offset + rdlength_bin_size) / 16
        next_record_idx = round(next_record_idx)
        # print("next_record_idx", next_record_idx)
        ip_bin = answer_bin_rows[next_record_idx - 2] + answer_bin_rows[next_record_idx - 1]
        ip_octet_list = re.findall('.'*8, ip_bin)
        ip_list = []
        print("ip_octet_list", ip_octet_list)
        for byte in ip_octet_list:  
            ip_list.append(str(int(byte, 2)))
            ip_address = '.'.join(ip_list)

        print("ip address", ip_address)

        print("ttl perhaps",int(r_ttl,16))
        print(f"IP\t {ip_address}\t caches sec {int(r_ttl,16)} auth\t{flags_values[2]}")

    elif type_value == "0002":  # Type NS
        pass
    elif type_value == "0005":  # Type CNAME
        pass
    elif type_value == "000f":  # Type MX
        pass
    
    print(f"{rdata_offset} + {rdlength_bin_size}, {j}")
    j += round((rdata_offset + rdlength_bin_size) / 16)  # update to get the index of the next record in the answer_bin_rows
    print("updated J", j)
print(r_name_list)





















print("DnsClient sending request for", domain_name)

print("Server",server_IP_address)

if    q_type== "000f":
    print("Request Type","MX")

elif  q_type == "0002":
    print("Request Type","NS")

else: ##or q_type == "0001"
    print("Request Type", "A")











print(f"Response received after {end - start} seconds [num_retries] not coded yet]")



##Get number of additional asnwer records
#print(f"***Answer Section ({int(header_response_flags_dict["ANCOUNT"],16)} record(s))***")
numanswers= int(header_response_flags_dict.get("ANCOUNT"),16)
print(f"***Answer Section ({numanswers}) record(s)***") 

##Type of response going to need a way to get the others too
TYPE_response = ''
if answer_bin_rows[1] == '0000000000000001':
    TYPE_response = 'A'
elif answer_bin_rows[1] == '0000000000000010':
    TYPE_response = 'NS'
elif answer_bin_rows[1] == '0000000000001111':
    TYPE_response = 'MX'
else: #if this doesnt work the conversion is 0000000000000101 in binary
    TYPE_response = 'CNAME'

##BAD CLASS ERROR
if answer_bin_rows[2] != '0000000000000001':
    print("ERROR\tUnexpected : was expecting response clas to be of type IN (internet), which is 0000000000000001 but got",answer_bin_rows[2])


globaindex=0 #in case of many records in aswers and having to go back each time.
##gonna need to use rlenght to understand how many rows we take for rdata






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