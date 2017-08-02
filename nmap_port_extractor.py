'''
Python version 3.5.2
This script parses a .nmap format scan, extracts the port numbers, 
ip addresses and exports them to a csv file under the ip's name.
'''
import re

x = 0
ips = []
portlist = 0
#path = str(input("Enter the relative or absolute path to the .nmap file: "))
path = "../../code/python/projects/multi_nmap/multi-tcp-port-discovery.nmap"

with open(path, "r") as file_input:
	for line in file_input:
		if "report " in line:
			ips.append((line.split("for ")[1]).rstrip())

ports = [[] for i in range(len(ips))]

with open(path, "r") as file_input:
	for line in file_input:		
		if line == '\n':
			portlist+=1
		if re.match("^[0-9]+", line):
			ports[portlist].append(line.split("/")[0])

# Output FILE FUNCTION
for i in range(len(ips)):	
	with open(ips[x], "w") as file_output:
		file_output.write(",".join(ports[x]))
	x+=1

print("portlist = ", portlist)
print(ports)