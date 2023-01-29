import sys
import socket
import random
import re
import time


def retrieve_domain_name(l, index, name):
    while index < len(l):
        # print(f"List used: {l}\nIndex used: {index}\nCurrent name: {name}")
        if l[index] == 0:
            return name
        elif l[index] == 192:
            index = l[index + 1]
            return retrieve_domain_name(msg_bytes, index, name)
        else:
            if l[index] < 32:
                segment_length = l[index]
                segment = l[index + 1: index + 1 + segment_length]
                # print("Segment", segment)
                segment = [chr(byte) for byte in segment]
                segment = "".join(segment) + "."
                name += segment
                index += 1 + segment_length
    return name


def parse_domain_name():
    r_name = ""
    returned_r_names = []
    record_num = 0
    i = 0

    while i < len(answer_in_bytes):
        # print(f"i: {i}\t Current byte: {answer_in_bytes[i]}")
        if answer_in_bytes[i] == 192:
            index = answer_in_bytes[i+1]
            # print("Index passed", index)
            r_name = retrieve_domain_name(msg_bytes, index, "")[:-1]
            returned_r_names.append(r_name)
            record_num += 1

        # Read the type, class, ttl, rdlength, rdata
        # print("answer", answer_in_bytes)
        r_type = answer_in_bytes[i + 2:i + 4]
        r_class = answer_in_bytes[i + 4:i + 6]
        r_ttl = answer_in_bytes[i + 6:i + 10]
        r_rdlength = answer_in_bytes[i + 10:i + 12]
        data_length = int.from_bytes(r_rdlength, 'big')
        # print("data length", data_length)
        r_data = answer_in_bytes[i + 12: i + 12 + data_length]

        # print(f"length type {len(r_type)}, length class {len(r_class)}, length ttl {len(r_ttl)}, length rdlength {len(r_rdlength)}, length data {len(r_data)}")
        # increment i to the next byte for the record
        i = i + len(r_type) + len(r_class) + len(r_ttl) + len(r_rdlength) + data_length + 2 
        # print(f"next i index: {i}")

        section = ""
        if record_num <= int(header_response_flags_dict["ANCOUNT"], 16):
            section = "Answer"
        else:
            section = "Additional"

        # print(f"Record {record_num}:")
        # print("Type", r_type)
        # print("Class", r_class)
        # print("TTL", r_ttl)
        # print("RDLength", r_rdlength)
        # print("RData", r_data)
        # print("RData", r_data)
        # print("Section", section)

        if r_type.hex() == "0005" or r_type.hex() == "0002":
            r_data = retrieve_domain_name(r_data, 0, "")[:-1]

        elif r_type.hex() == "000f":
            pref = r_data[0:2]
            exchange = retrieve_domain_name(r_data[2:], 0, "")[:-1]
            r_data = [pref, exchange]

        record_dict_values = [r_name, r_type, r_ttl, r_data, section]
        record_dict = dict(zip(record_dict_keys, record_dict_values))
        records_dict[str(record_num)] = record_dict

def output_error_msg(error_msg):

    if error_msg == "TIMEOUT":
        print("ERROR \t Timeout")
    
    elif error_msg == "RETRY":
        print("ERROR \t Maximum number of retries")
    return


def output_records_info(section, num_of_records):
    print(f"***{section} Section ({num_of_records} record(s))***")
    for key, value in records_dict.items():
        if value["Section"] != section: continue
        record_type = value["Type"].hex() 
        ttl = int(value["TTL"].hex(), 16)
        auth_value = header_response_flags_dict["AA"]
        auth = "nonauth" if auth_value else "auth"

        if record_type == "0001": # Type A
            ip_list = []
            for byte in value["Data"]:  
                ip_list.append(str(byte))
                ip_address = '.'.join(ip_list)
            print(f"IP \t [{ip_address}] \t [{ttl}] \t [{auth}]")

        elif record_type == "0002":  # Type NS
            alias = value["Data"]
            print(f"NS \t [{alias}] \t [{ttl}] \t [{auth}]")

        elif record_type == "0005":  # Type CNAME
            alias = value["Data"]
            print(f"CNAME \t [{alias}] \t [{ttl}] \t [{auth}]")

        elif record_type == "000f":  # Type MX
            pref = value["Data"][0]
            alias = value["Data"][1]
            # MX <tab> [alias] <tab> [pref] <tab> [seconds can cache] <tab> [auth | nonauth]
            print(f"MX \t [{alias}] \t [{pref}] \t [{ttl}] \t [{auth}]")


def output_message():
    print("DnsClient sending request for", domain_name)
    print("Server",server_IP_address)
    request_type = "Request Type"
    if q_type== "000f":
        print(request_type,"MX")

    elif q_type == "0002":
        print(request_type,"NS")

    else: ##or q_type == "0001"
        print(request_type, "A")

    time = end - start
    time = "{:.2}".format(time)
    print(f"Response received after {time} seconds ({retries} retries)")

    # Answer Section # 
    num_of_answers = int(header_response_flags_dict["ANCOUNT"], 16)
    if num_of_answers > 0:
        output_records_info("Answer", num_of_answers)

    # Additional Section # 
    num_of_additionals = int(header_response_flags_dict["ARCOUNT"], 16)
    if num_of_additionals > 0:
        output_records_info("Additional", num_of_additionals)
    
    if num_of_additionals + num_of_answers == 0: print("NOTFOUND")

try:
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

    ## DNS Questions parsed
    dns_question = q_name + q_type + q_class

    # Header Preparation
    dns_header = ""

    id = hex(random.getrandbits(16)).strip("0x").zfill(4)
    flags = '0100'
    qdcount = '0001' 
    ancount = '0000' 
    nscount = '0000' 
    arcount = '0000' 

    dns_header = id + flags + qdcount + ancount + nscount + arcount
    dns_packet =  dns_header + dns_question
    dns_packet_bytes = bytes.fromhex(dns_packet)

    # UDP Client 
    server_Port = switches_values_dict["-p"]
    bytes_to_send = dns_packet_bytes
    server_Address_Port = (server_IP_address,server_Port)
    udp_carl = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    bufferSize = 1024

    ## Send to server using created UDP 
    retries = 0
    while retries <= switches_values_dict["-r"]:
        try:
            start = time.time()
            udp_carl.sendto(bytes_to_send, server_Address_Port)
            msgFromServer = udp_carl.recvfrom(bufferSize)
            end = time.time()

            if (end - start) > switches_values_dict["-t"]:
                raise TimeoutError
            
            msg = msgFromServer[0]
            msg_hex = msg.hex()
            msg_bin = format(int(msg_hex, 16), '0>16b')
            # print(msg)
            # print("Server Message", msg)
            # print("Server Message in Binary", msg_bin)
            # print("Server Message in Hex", msg_hex)

            # Parsing the response packet

            # Initialising dict to keep track of header values for OUTPUT
            head_response_flags_keys = ["ID", "QR", "OPCODE", "AA", "TC", "RD", "RA", "Z", 
                                "RCODE", "QDCOUNT", "ANCOUNT", "NSCOUNT", "ARCOUNT"]
            initial_values = [""]*len(head_response_flags_keys)
            header_response_flags_dict = dict(zip(head_response_flags_keys, initial_values))

            ## Decoding the header response
            header_response_rows = re.findall('.'*4, msg_hex[:24])
            flags_values = bin(int(header_response_rows[1], 16)).lstrip("0b")
            # print("header response rows", header_response_rows)

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
            # print("Flags Values", header_response_flags_dict)

            msg_bytes = bytearray(msg)
            answer_in_bytes = msg_bytes[len(dns_packet_bytes):]

            records_dict = {}
            record_dict_keys = ["Name", "Type", "TTL", "Data", "Section"]

            parse_domain_name()
            output_message()
            break
        except Exception:
            retries += 1
            
    if retries > switches_values_dict["-r"]: 
        raise output_error_msg("RETRY")
except Exception:
    pass
    


