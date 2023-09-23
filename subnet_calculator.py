# [ Name ]:             Subnet Calculator 
# [ Version ]:          1.0
# [ Author ]:           Christian Goeschel Ndjomouo
# [ Created on ]:       Sep 17 2023
# [ Last updated on ]:  Sep 19 2023
# [ Tested on ]:        Python v3.9
#
# [ Description ]:      This program takes a random IPv4 address, subnet mask in DDN or CIDR as input.
#                       It then returns detailed information about the network like the network ID, network range, first and last 
#                       useable host addresses, total amount of hosts, total amount of useable hosts, broadcast address,
#                       Subnet Mask in DDN and CIDR notation, and binary versions of the IPv4 address, network ID and the subnet mask.
#              
#                       More features may be added in the future.


# Importing needed modules
from functools import reduce
import sys
import re
import time

# Function to retrieve IP and Subnet Mask
def input_req():

    global ip_input
    global sm_input
    
    ip_input = input("""
            [ SUBNET CALCULATOR ]\n
            Please type in an IPv4 address\n
            [ Allowed format ]: 
                     
            DDN:    XXX.XXX.XXX.XXX\n
            Type in here: """)
    
    
    sm_input = input("""\n
            Please type in the Subnet Mask.\n
            [ Allowed formats ]:

            DDN:    XXX.XXX.XXX.XXX
            CIDR:   /XX \n
            Type in here: """)
    
    return ip_input, sm_input

# Function that simulates a loader
def loader():

    print("\nCalculating subnet information")
    time.sleep(.5)
    print(".")
    time.sleep(.5)
    print(".")
    time.sleep(.5)
    print(".",end="\n")


# Function for the splitting of the octects or CIDR notation numeric values from ' . ' or ' / '
def splitter(valid_input):

    valid_ip = valid_input[0]
    valid_sm = valid_input[1]

    valid_ip = valid_ip.split('.')      # Splits each octet apart, the delimiter is ' . ' 
    
    # If the length is greater than 3 it cannot be a CIDR notation but the subnet mask in DDN
    if len(valid_sm) > 3:
        valid_sm = valid_sm.split('.')  # Splits each octet apart, the delimiter is ' . ' 
    
    else:
        valid_sm = valid_sm.split('/')  # Splits the numeric value from the ' / ' 
        del valid_sm[0]

    return valid_ip, valid_sm


# This function calculates the first and lost host of the network range
def calc_hosts_bin(bin_net_id, bin_brdcst, cidr):

    global first_host_bin       # First useable host in binary
    global last_host_bin        # Last useable host in binary

    if cidr != 32:
        # Flipping last binary value into a one
        first_host_bin = bin_net_id[0:-1] + "1"
        last_host_bin = bin_brdcst[0:-1] + "0" 

    else:
        first_host_bin = bin_net_id
        last_host_bin = bin_brdcst


# This function converts all binary octets in to a dotted decimal notation
def bin_to_decimal(binary_value):

    global final_decimal_value
    global temp_octet_store

    final_decimal_value = ""    # Final Dotted Decimal Notation of the IPv4 addresses or subnet mask ( DDN )
    temp_octet_store = ""       # Temporary variable that holds the binary value of the single octet

    for i in range(0,4):    # Iterates 4 times because it has to convert four octects
        for binary in range(0,8):   # Iterates 8 times because it has to collect 8 bits for each octet

            temp_octet_store += binary_value[binary]
        
        if i != 3:
            # Appending the converted decimal octet
            final_decimal_value += str(int(temp_octet_store, 2)) + "."
          
            # Stripping away the leading octet that has already been converted
            binary_value = binary_value[8:]
      
            # Clearing the temporary octet store for the next conversion
            temp_octet_store = ""
            
            continue

        else:
           # Appending the converted decimal octet
            final_decimal_value += str(int(temp_octet_store, 2))
          
            # Stripping away the leading octet that has already been converted
            binary_value = binary_value[8:]
      
            # Clearing the temporary octet store for the next conversion
            temp_octet_store = ""
            
            continue
    
    return final_decimal_value
            

# This function will iterate through the binary IPv4 as many times as submask_counter of the user defined CIDR notation
# To get the Network ID
def calc_net_id(ipv4_bin, cidr):

    global net_id_bin
    net_id_bin = ""

    for i in range(0, cidr):

        net_id_bin += ipv4_bin[i]                       # Will count each bit in the Binary IPv4 and get the network ID part
                                                        # the amount of time it counts is defined by the counter parameter which is the CIDR notation
    if len(net_id_bin) < 32:                            

        net_id_bin += "0" * ( 32 - len(net_id_bin))     # Will fill the host part of the Network ID with '0's


# This function will create a binary subnet mask from the CIDR notation
def create_bin_submask(cidr):
    
    global binary_netmask

    if cidr == 0:
        binary_netmask = "0" * 32   

    elif cidr == 32:                    # CIDR notatin /32
        binary_netmask = "1" * 32   # This will result in 11111111 11111111 11111111 11111111 => 255.255.255.255
    
    else:
        binary_netmask = "1" * cidr + "0" * ( 32 - cidr )   # Fills as many octets with '1's as the CIDR notation defines, the rest default to '0's


# This function will iterate through the Binary IPv4 as many times as submask_counter of the user defined CIDR notation
# to get the Network ID 
def calc_broadcast(ipv4_bin, cidr):

    global broadcast_bin
    broadcast_bin = ""

    for i in range(0, cidr):

        broadcast_bin += ipv4_bin[i]

    if len(broadcast_bin) < 32:

        broadcast_bin += "1" * ( 32 - len(broadcast_bin))


# Function for calculating the network ID, network range, broadcast and CIDR notation value
def calc_info(ipv4, submask):

    global binary_netmask
    global bin_ipv4
    global cidr

    binary_netmask = ""
    cidr = 0

    if ipv4 and submask:
       
        # Binary IPv4
        bin_ipv4 = str('{0:08b}{1:08b}{2:08b}{3:08b}'.format( int(ipv4[0]), int(ipv4[1]), int(ipv4[2]), int(ipv4[3])  ))

        if len(submask) > 3:
            
            # Binary Subnet Mask ( Non CIDR )
            binary_netmask = str( '{0:08b}{1:08b}{2:08b}{3:08b}'.format( int(submask[0]), int(submask[1]), int(submask[2]), int(submask[3]) ) )
            
            cidr = reduce( lambda bit_count, bit: bit_count + int(bit), binary_netmask, 0 ) # More information on this function down below under [cidr]
            
            calc_net_id(bin_ipv4, cidr)                             # Calculates the binary version of the Network ID
            calc_broadcast(bin_ipv4, cidr)                          # Calculates the binary version of the Broadcast
            calc_hosts_bin(net_id_bin, broadcast_bin, cidr)         # Calculating the first and last hosts binary values    
        
        else:

            # This will determine the amount of times the calc_net_id() function will have to iterate through the bin_ipv4
            # in order to get the Network ID
            cidr = int(submask[0])
            calc_net_id(bin_ipv4, cidr)                             # Calculates the binary version of the Network ID
            calc_broadcast(bin_ipv4, cidr)                          # Calculates the binary version of the Broadcast
            calc_hosts_bin(net_id_bin, broadcast_bin, cidr )        # Calculating the first and last hosts binary values
            create_bin_submask(cidr)                                # Creates a binary subnet mask

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

    # Applying the regex for the IPv4, CIDR, and subnet mask respectfully 
    # The returned data type is a <bool>
    ip_regex_result = re.search(f"^{ip_regex_str}\\.{ip_regex_str}\\.{ip_regex_str}\\.{ip_regex_str}$", user_input[0]) 
    cidr_regex_result = re.search(f"^{cidr_regex_str}$", user_input[1])
    sm_regex_result = re.search(f"^{sm_regex_str}\\.{sm_regex_str}\\.{sm_regex_str}\\.{sm_regex_str}$", user_input[1])


    if ip_regex_result and cidr_regex_result or sm_regex_result:

        loader()
        calc_info( *splitter(user_input) ) # Return the user_input list to the splitter() function for further processing 

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
    print("Subnet Mask:\t\t", bin_to_decimal(binary_netmask), end="\n")
    print("CIDR Notation:\t\t", "/" + str(cidr), end="\n")
    print("\nTotal Hosts:\t\t", ( 2 ** ( 32 - cidr ) ), end="\n")
    print("Total Useable Hosts:\t", ( ( 2 ** ( 32 - cidr ) ) - 2 ), end="\n")
    print("\nIPv4 in Binary:\t\t", bin_ipv4, end="\n")
    print("Network ID in Binary:\t", net_id_bin, end="\n")
    print("Subnet Mask in Binary:\t", binary_netmask, end="\n")


# Calling the check_input function with the return values from input_req() as arguments
# ' * ' unpacks the return values in their positional order 
check_input(*input_req())

# Printing all the gathered information
print_info()





# [ Function(s) / variable(s) descriptions ]
#
#
#   [ Variable(s) ]
#
#   >>> [ cidr ]:
#                   This  lambda function 'reduce' will take a lambda expression as parameter, the iterable 
#                   object 'binary_netmask' and the starting value for the bit_count variable found in the lambda expression,
#                   in respective order.
#
#                   The lambda function creates a variable 'bit_count' to represent the SUM of all binary values added up in the 
#                   subnet mask ( binary_netmask ) to denote the CIDR notation ( RFC 1519 ).
#
#                   Since 'binary_netmask' is a <str> object it is iterable and appropriate to use in the 'reduce' function.
#                   However, 'bit_count' is an <int> object and 'bit' which is equal to the iterated character from 'binary_netmask'
#                   needs to be converted to the <int> type before it can be added with 'bit_count'. 
#
#                   The '0' at the end is the assigned initial value of 'bit_count'.
# 
