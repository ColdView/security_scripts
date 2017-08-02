## Security Scripts

1. #### convert_chars_to_unicode.py 
   This script is helpful when evading xss filters.

2. #### nmap_port_extractor.py
   This script parses a .nmap format scan and extracts the port numbers and ip addresses. It then exports the list of ports to a csv file under the name of their corresponding ip address, in the cwd. This list is suitable as an input to a further nmap scan e.g. -p $(cat ip-address.txt).
