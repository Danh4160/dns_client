import sys

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
if flags_values_dict["-mx"]: qType = "0x000f"
elif flags_values_dict["-ns"]: qType = "0x0002"
else: qType = "0x0001"

qClass = "0x0001"
qName = ""

domain_name_sliced = domain_name.split(".")
for slice in domain_name_sliced:
    slice_length = str(len(slice))
    # print(hex(slice_length))
    # print(slice.encode().hex())
    qName += slice_length + slice


print(qName)
print(qName.encode("utf-8").hex())
# print(bytes.fromhex(qName))


