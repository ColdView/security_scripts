'''
Python version 3.5.2
This script parses a .nmap format scan, extracts the port numbers 
and exports them to a csv file.
'''
import re

ports = []
path = str(input("Enter the relative or absolute path to the .nmap file: "))

with open(path, "r") as file_input:
	for line in file_input:
		if re.match("^[0-9]+", line):
			[ports.append(line.split("/")[0])]

with open("port-list.txt", "w") as file_output:
	file_output.write(",".join(ports))
