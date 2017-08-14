'''
This script parses a .nmap format scan, extracts the port numbers, 
ip addresses and exports the ports to a csv file under the ip's name.
'''
import re

ips = []
x = -1
path = str(input("Enter the relative or absolute path to the .nmap file: "))
ports = []
#-----------------Pull IPs and Ports, append to lists------------------
with open(path, "r") as nmap_scan:
	for line in nmap_scan:
		if "scan report " in line:
			ips.append((line.split("for ")[1]).rstrip())
			ports.append([])
			x+=1
		if re.match("[0-9]+/", line):
			ports[x].append(line.split("/")[0])

#---------------Write non-empty port lists to ip files-----------------
for i in range(len(ips)):	
	if len(ports[i]) > 0:
		with open(ips[i], "w") as file_output:
			file_output.write(",".join(ports[i]))
	else:
		continue
