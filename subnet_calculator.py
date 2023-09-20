# Tested on Python Version 3.9
# Author: Christian Goeschel Ndjomouo
# Sep 19 2023
# Description: This program takes a random IPv4 address, Subnet Mask and/or CIDR as input
#              Returns detailed information about the Network like the Network ID, Network range, First and Last 
#              useable host addresses,total amount of hosts, total amount of useable hosts, broadcast address,
#              Subnet Mask and CIDR notation. More features may be added in the future.

# Importing needed modules
import sys
import re

# Function to retrieve IP and Subnet Mask
def input_req():

    global ip_input
    global sm_input

    ip_input = input("""Please type in an IPv4 address\n
                     [ Allowed format ]

                     Standard: XXX.XXX.XXX.XXX\n
                     Type in here: """)
    
    
    sm_input = input("""\nNow, please type in the Subnet Mask.\n
                     [ Allowed formats ]

                     Standard: XXX.XXX.XXX.XXX
                     CIDR: /XX \n
                     Type in here: """)
    
    return ip_input, sm_input


# Function for the splitting of the octects or CIDR notation numeric values from ' . ' or ' / '
def splitter(valid_input):

    valid_ip = valid_input[0]
    valid_sm = valid_input[1]

    valid_ip = valid_ip.split('.')  # Splits the numeric values from the ' . ' out of each octet
    
    # If the length is greater than 3 it cannot be CIDR but the traditional Subnet mask
    if len(valid_sm) > 3:
        valid_sm = valid_sm.split('.')  # Splits the numeric values from the ' . ' out of each octet
    
    else:
        valid_sm = valid_sm.split('/')  # Splits the numeric value from the ' / ' 
        del valid_sm[0]

    return valid_ip, valid_sm


# This function converts the subnet mask into binary and calculates the CIDR 
# by counting how many occurences of "1" there are 
def sm_bin_converter(sm_bin):

    sm_counter = 0

    for i in range(0,32):

        if "1" in sm_bin[i]:    # Everytime there is a '1' the counter goes up, the end result equals to the CIDR notation

            sm_counter += 1 

        else:
            continue
    
    return sm_counter


# This function calculates the first and lost host of the network range
def calc_hosts_bin(bin_net_id, bin_brdcst, cidr_notation):

    global first_host_bin
    global last_host_bin
    global cidr

    cidr = cidr_notation

    if cidr != 32:
        # Flipping last binary value into a one
        first_host_bin = bin_net_id[0:-1] + "1"
        last_host_bin = bin_brdcst[0:-1] + "0" 

    else:
        first_host_bin = bin_net_id
        last_host_bin = bin_brdcst


# This function converts all binary octets in to decimal notation
def bin_to_decimal(binary_value):

    global final_decimal_value
    global temp_octet_store

    final_decimal_value = ""
    temp_octet_store = ""

    for i in range(0,4):
        for binary in range(0,8):

            temp_octet_store += binary_value[binary]
        
        if i != 3:
            # Appending the converted decimal octet
            final_decimal_value += str(int(temp_octet_store, 2)) + "."
          
            # Stripping the leading octets
            binary_value = binary_value[8:]
      
            # Clearing the temporary octet store for the next conversion
            temp_octet_store = ""
            
            continue

        else:
           # Appending the converted decimal octet
            final_decimal_value += str(int(temp_octet_store, 2))
          
            # Stripping the leading octets
            binary_value = binary_value[8:]
      
            # Clearing the temporary octet store for the next conversion
            temp_octet_store = ""
            
            continue
    
    return final_decimal_value
            

# This function will iterate through the Binary IPv4 as many times as submask_counter of the user defined CIDR notation
# To get the Network ID
def calc_net_id(ipv4_bin, counter):

    global net_id_bin
    net_id_bin = ""

    for i in range(0, counter):

        net_id_bin += ipv4_bin[i]                       # Will count each bit in the Binary IPv4 and get the network ID part
                                                        # the amount of time it counts is defined by the counter parameter which is the CIDR notation
    if len(net_id_bin) < 32:                            

        net_id_bin += "0" * ( 32 - len(net_id_bin))     # Will fill the host part of the Network ID with '0's


# This function will create a binary subnet mask from the CIDR notation
def create_bin_submask(cidr):
    
    global binary_subnet_mask

    if cidr == 0:
        binary_subnet_mask = "0" * 32   

    elif cidr == 32:                    # CIDR notatin /32
        binary_subnet_mask = "1" * 32   # This will result in 11111111 11111111 11111111 11111111 => 255.255.255.255
    
    else:
        binary_subnet_mask = "1" * cidr + "0" * ( 32 - cidr )       # Fills as many octets with '1's as the CIDR notation defines, the rest default to '0's


# This function will iterate through the Binary IPv4 as many times as submask_counter of the user defined CIDR notation
# To get the Network ID
def calc_broadcast(ipv4_bin, counter):

    global broadcast_bin
    broadcast_bin = ""

    for i in range(0, counter):

        broadcast_bin += ipv4_bin[i]

    if len(broadcast_bin) < 32:

        broadcast_bin += "1" * ( 32 - len(broadcast_bin))


# Function for calculating the network ID, network range, broadcast, CIDR etc...
def calc_bin(ipv4, submask):

    global binary_subnet_mask
    global bin_submask
    global bin_ipv4
    bin_submask = ""

    global submask_counter
    submask_counter = 0

    if ipv4 and submask:
       
        # Binary IPv4
        bin_ipv4 = str('{0:08b}{1:08b}{2:08b}{3:08b}'.format( int(ipv4[0]), int(ipv4[1]), int(ipv4[2]), int(ipv4[3])  ))

        if len(submask) > 3:
            
            # Binary Subnet Mask ( Non CIDR )
            bin_submask = str( '{0:08b}{1:08b}{2:08b}{3:08b}'.format( int(submask[0]), int(submask[1]), int(submask[2]), int(submask[3]) ) )
            binary_subnet_mask = bin_submask
            calc_net_id(bin_ipv4, sm_bin_converter(bin_submask))        # Calculates the binary version of the Network ID
            calc_broadcast(bin_ipv4, sm_bin_converter(bin_submask))     # Calculates the binary version of the Broadcast
            
            
            calc_hosts_bin( net_id_bin, broadcast_bin, sm_bin_converter(bin_submask) )  # Calculating the first and last hosts binary values
            submask_counter = sm_bin_converter(bin_submask)                             # Sets the CIDR notation variable
    
        else:

            # This will determine the amount of times the calc_net_id() function will have to iterate through the bin_ipv4
            # in order to get the Network ID
            submask_counter = int(submask[0])
            calc_net_id(bin_ipv4, submask_counter)                             # Calculates the binary version of the Network ID
            calc_broadcast(bin_ipv4, submask_counter)                          # Calculates the binary version of the Broadcast
            calc_hosts_bin(net_id_bin, broadcast_bin, submask_counter )        # Calculating the first and last hosts binary values
            create_bin_submask(submask_counter)                                # Creates a binary subnet mask

    else:
        print("[ FATAL ERROR ] Aborting ...")
        sys.exit()


# Function to check user input validity
def check_input(ip, sm):

    user_input = [ip, sm]

    # Regex pattern for IPv4 input validation algorithm
    ip_regex_str = "([0-9]|1[0-9]{0,2}|[2-9][0-9]|2[0-4][0-9]|25[0-5])"
    
    # Regex pattern for CIDR input validation algorithm
    cidr_regex_str = "\\/([1-9]|1[0-9]|2[0-9]|3[0-2])"

    # Regex pattern for Subnet Mask input validation algorithm
    sm_regex_str = "(0|128|192|224|240|248|252|254|255)"

    # Applying the regex for IPv4, CIDR, and Subnet Mask respectfully 
    # The stored data type resolves to a <bool>
    ip_regex_result = re.search(f"^{ip_regex_str}\\.{ip_regex_str}\\.{ip_regex_str}\\.{ip_regex_str}$", user_input[0]) 
    cidr_regex_result = re.search(f"^{cidr_regex_str}$", user_input[1])
    sm_regex_result = re.search(f"^{sm_regex_str}\\.{sm_regex_str}\\.{sm_regex_str}\\.{sm_regex_str}$", user_input[1])


    if ip_regex_result and cidr_regex_result or sm_regex_result:

        print("\n[ Processing ... ]")
        calc_bin( *splitter(user_input) ) # Return the user_input list to the splitter() function for further processing 

    else:
        print("\n[ ERROR ] Illegal input. Stopping program execution... [ ERROR ]")
        sys.exit()          # Stopping the program all together
            

# This function will gather all the information and print it to standard output
def print_info():
    
    print("\nIPv4 Address:\t\t",ip_input, end="\n\n")
    print("Network ID:\t\t", bin_to_decimal(net_id_bin) , end="\n")
    print("First Host:\t\t", bin_to_decimal(first_host_bin) , end="\n")
    print("Last Host:\t\t", bin_to_decimal(last_host_bin) , end="\n")
    print("Broadcast:\t\t", bin_to_decimal(broadcast_bin) , end="\n")
    print("Subnet Mask:\t\t", bin_to_decimal(binary_subnet_mask), end="\n")
    print("CIDR Notation:\t\t", "/" + str(submask_counter), end="\n")
    print("\nTotal Hosts:\t\t", ( 2 ** ( 32 - submask_counter ) ), end="\n")
    print("Total Useable Hosts:\t", ( ( 2 ** ( 32 - submask_counter ) ) - 2 ), end="\n")
    print("\nIPv4 in Binary:\t\t", bin_ipv4, end="\n")
    print("Network ID in Binary:\t", net_id_bin, end="\n")
    print("Subnet Mask in Binary:\t", binary_subnet_mask, end="\n")


# Calling the check_input function with the return values from input_req() as arguments
# ' * ' unpacks the return values in their positional order 
check_input(*input_req())

# Printing all the gathered information
print_info()