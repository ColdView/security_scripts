## Security Scripts

1. #### convert_chars_to_unicode.py 
   This script is helpful when evading xss filters.

2. #### nmap_port_extractor.py
   This script parses a .nmap format scan and extracts the port numbers and ip addresses. It then exports the list of ports to a csv file under the name of their corresponding ip address, in the cwd. This list is suitable as an input to a further nmap scan e.g. -p $(cat ip-address.txt).

3. #### auto_nmap.py 
   This script first runs a host scan against an ip range provided as a cli argument. It then uses the live hosts returned as input for a further scan based on the nmap options given in the second cli argument. The second scan is then parsed with info output to html including links to potential exploits based on the services' Common Platform Enumeration string. Curently working with -sV option. (When issuing the second argument use the escape string (--) before the list of nmap options as shown in usage!)