import sys
import socket
import random

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
            server_IP_address = sys.argv[i]
        else:
            domain_name = sys.argv[i]


# DNS Questions Preparation
if flags_values_dict["-mx"]: q_type = "0x000f"
elif flags_values_dict["-ns"]: q_type = "0x0002"
else: q_type = "0x0001"

q_class = "0x0001"
q_name = ""

domain_name_sliced = domain_name.split(".")
for slice in domain_name_sliced:
    slice_length = str(len(slice))
    q_name += slice_length + slice

q_name += "0"

q_name_as_bytes = str.encode(q_name)

print(q_name_as_bytes)




#Header


##Should fromat this a different way maybe hardcode most of the already know bits into all in one
## for example if theyr are consecutive known stuff we put them all in one variable

##Random 16-bit number 
##NOT SURE IF getrandbits ACTUALLY DOES WHAT I EXEPECT
id = '' + random.getrandbits(16)


##All of this is 16 bit could put it all together now
QR = '0'
OPcode='0000'
AA='0'
TC='0'
RD='1'
RA='0'
Z ='000'
RCODE='0000'

##Cumulation of everything above except ID
AllBITCODES = "0000000100000000"


##Each of these are 16 bit
QDCOUNT='0000000000000001' ##should be 1
ANCOUNT='0000000000000000' ##values dependent on answer
NSCOUNT='0000000000000000' ##values dependent on answer however program can ignore response entries in this section
ARCOUNT='0000000000000000' ##values dependent on answer


##Constucxt QNAME Size|Label|Size|Label 
##DO NOT FORGET TERMINATING 0 BYTE. 







##Append full message





# UDP Client 
server_Port = flags_values_dict["-p"]

client_msg = "Harsh is gay"
send_msg = str.encode(client_msg)
server_Address_Port = (server_IP_address, server_Port)

udp_carl = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Send to server 
udp_carl.sendto(send_msg, server_Address_Port)

