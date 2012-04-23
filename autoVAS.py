#!/usr/bin/python

# Author: Andre Guerlain
# Date: March 21, 2012
# This script is designed for the OpenVAS module of our Vulnerability Assessment Tool
#
# Format: ./openvas-script.py <target ip> <scan>
#
#	There are four built in scans with openVAS, the numbers 1-4 represent them.
#	There are four possible inputs for this script(input	-resulting scan)
#		1	-daba56c8-73ec-11df-a475-002264764cea  Full and fast
#		2	-698f691e-7489-11df-9d8c-002264764cea  Full and fast ultimate
#		3	-708f25c4-7489-11df-8094-002264764cea  Full and very deep
#		4	-74db13d6-7489-11df-91b9-002264764cea  Full and very deep ultimate


import re, string, sys, subprocess, shlex, time, io


"""
####################################################################
## Helper  
## Functions 
####################################################################
"""


####################################################################
# Help Function
####################################################################
# This function is invoked by the -h or --help flags, and prints out
# helpful information for the user.
def helpFunc():
	print "Usage: openvas-script.py [OPTION1] [OPTION2] [OPTION3]"
	print "Use to automatically run OpenVAS on a given target ip OPTION1, with"
	print "a given scan configuration [OPTION2] and an optional flag [OPTION3]\n"
	print "The first two arguments are required.  Option 1 must be a valid ip and"
	print "option 2 must be a valid scan configuration, represented by an integer"
	print "between and including 1 and 4"
	print "Example: python openvas-script.py 100.200.111.222 2 -v"
	print "Example: python openvas-script.py -h\n"
	print "Optional flags:"
	print "-h, --help		Prompt for this message"
	print "-v, --verbose		Print additional information while running \n"
	print "Written by Andre Guerlain"
	return


####################################################################
# Checking if IP is valid
####################################################################
# This function is designed to take in an IP and check to make sure
# the format and numbers are valid, so that the program can attempt
# to sucessfully scan that location
def isValidIP(ip):
	valid = 1
	global errNote
	ip = ip + "/32"
	sections = ip.split("/")
	if(not (sections[1].isdigit() and int(sections[1]) >= 0 and int(sections[1]) <= 32)):
		valid = 0;
		errNote = "Given ip is invalid: Make sure the end is a number between /0 and /32"
	ipParts = sections[0].split(".")
	if(len(ipParts) == 4):
		for part in ipParts:
			if(not (part.isdigit() and int(part) >= 0 and int(part) < 256)):
				valid = 0;
				errNote = "Given ip is invalid: Make sure the ip consists of four octets,\neach a number within the range 0-255 inclusive"
	else:
		valid = 0;
		errNote = "Given ip is invalid: Make sure to include all four octets, even with a /xx at the end"
	return valid


####################################################################
# Checking if scan flag is valid
####################################################################
# This function is given a scan id, in other words one of the inputs
# provided by the user, and checks to see if it is valid
def isValidScan(scn):
	valid = 1
	global errNote
	if(scn.isdigit()):
		s = int(scn)
	if(s > 0 and s < 5):
		valid = 1
	else:
		valid = 0
		errNote = "Given scan configuration is invalid: Make sure the number falls between 1 and 4 (inclusive)."
	return valid


####################################################################
# Run a command
####################################################################
# This function is given a bash command and runs it.  In order to run
# the command correctly, it must first split the arguments and then
# open up a subprocess in bash.  It returns the output as a string.
def runCMD(rawcmd):
	cmd = shlex.split(rawcmd)
	task = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	retVal = task.communicate()[0]
	return retVal
	

####################################################################
# Run a command, piped to a second command
####################################################################
# This function is given two bash command and runs them by piping
# the output of the first command to the second one. In order to run
# the commands correctly, it must first split the arguments of both
# before running either. Then, the first command is run and the
# output is directed to a stream 'subprocess.PIPE'.  Before the
# second command can run, the first command must have finished.
# The function checks this, then runs the second command.
def runAndPipeCMD(firstCMD, secondCMD):
	cmd1 = shlex.split(firstCMD)
	cmd2 = shlex.split(secondCMD)
	
	firstTask = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	secondTask = subprocess.Popen(cmd2, stdin=firstTask.stdout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)	

	firstTask.stdout.close()	
	retVal = secondTask.communicate()[0]
	
	firstTask.wait()
	secondTask.wait()
	return retVal


"""
####################################################################
## Initializing  
## Configuration 
####################################################################
"""


####################################################################
# Checking Arguments
####################################################################
# There must be atleast one argument (The ip) and the optional second
# argument for the scan configuration

argc = len(sys.argv)
verbose = 0

# if --help flag
for item in sys.argv:
	if(item == "--help" or item == "-h"):
		helpFunc()
		sys.exit()

print "Initializing configuration"


if(argc < 3): #Case 1: Too few arguments given
	sys.exit("Too few arguments given: Please provide an ip address")
elif(argc == 3):
	if(isValidIP(sys.argv[1]) and isValidScan(sys.argv[2])):  #Check ip address is valid
		targetIP = sys.argv[1]  #set ip to argv[1]
		config = int(sys.argv[2]) - 1  #set config to default(1)
	else:
		sys.exit("Error: " + errNote)
elif(argc == 4):
	if(isValidIP(sys.argv[1]) and isValidScan(sys.argv[2])):
		targetIP = sys.argv[1]
		config = int(sys.argv[2]) - 1
		if(sys.argv[3] == "--verbose" or sys.argv[3] == "-v"):
			verbose = 1
		else:
			print "Warning, invalid flag given \"", sys.argv[3], "\""
	else:
		sys.exit("Error: " + errNote)
else:
	sys.exit("Too many arguments: Max 2")

####################################################################
# Finding format id for text
####################################################################
# OpenVAS reports can be retrieved in various formats, identitfied
# by format id's. To make sure the correct id is used to get text,
# this section retrieves that information

rawCMD1 = "omp -F"
rawCMD2 = "grep TXT"
result = runAndPipeCMD(rawCMD1, rawCMD2)
format_ID = result[0:36]
if(verbose):
	print "Format ID:", format_ID
####################################################################
# Creating list of configurations
####################################################################
# OpenVAS comes with four basic configurations.  Each one is checked
# make sure it exists and then appended into the list.

configList = []
configList.append("Full\ and\ fast")					#omp --get-configs | grep -m 1 Full\ and\ fast | cut -c 1-36
configList.append("Full\ and\ fast\ ultimate")			#omp --get-configs | grep -m 1 Full\ and\ fast\ ultimate | cut -c 1-36
configList.append("Full\ and\ very\ deep")				#omp --get-configs | grep -m 1 Full\ and\ very\ deep | cut -c 1-36
configList.append("Full\ and\ very\ deep\ ultimate")	#omp --get-configs | grep -m 1 Full\ and\ very\ deep\ ultimate | cut -c 1-36

rawCMD1 = "omp -g"
rawCMD2 = "grep -m 1 " + configList[config]


result = runAndPipeCMD(rawCMD1, rawCMD2)
config_ID = result[0:36]
if(verbose):
	print "Config ID:", config_ID
####################################################################
# Creating target based on given ip
####################################################################
# OpenVAS requires a target for each task, namely an ip or range of 
# ip's.  Here a target is created for the given ip(s).

#omp --xml="<create_target> <name>Test...</name> <hosts>157.55.56.149</hosts> </create_target>"
if(verbose):
	print "Creating target at ip", targetIP
else:
	print "Creating target"
rawCMD = "omp --xml=\"<create_target> <name>Test...</name> <hosts>" + targetIP + "</hosts> </create_target>\""


result = runCMD(rawCMD)

target_ID = result[result.find("id=\"") + 4:result.find("id=\"") + 40]
if(verbose):
	print "Target ID:", target_ID

"""
####################################################################
## Creating 
## Task   
####################################################################
"""

if(verbose):
	print "Creating task: Configuration ID", config + 1, "Target ID", target_ID
else:
	print "Creating task"
rawCMD = "omp --xml=\"<create_task> <name>temp</name> <comment>temporary task</comment> <config id='" + config_ID + "'/> <target id='" + target_ID + "'/></create_task>\""


result = runCMD(rawCMD)

task_ID = result[result.find("id=\"")+4:result.find("id=\"")+40]
if(verbose):
	print "Task ID:", task_ID

"""
####################################################################
## Starting 
## Task   
####################################################################
"""

if(verbose):
	print "Starting task: task id", task_ID
else:
	print "Starting task"
rawCMD = "omp --xml=\"<start_task task_id='" + task_ID + "'/>\""

result = runCMD(rawCMD)

report_ID = result[result.find("id>")+3:result.find("id>")+39]
if(verbose):
	print "Report ID:", report_ID

####################################################################
# Wait for the task to be "Done"
####################################################################
# OpenVAS does not generate a report for a task until it is done,
# meaning the script must wait until it has finished, using a while
# loop.

thirds = 0
rawCMD = "omp --get-tasks"

result = runCMD(rawCMD)
resList = result.split("  ")

while(resList[1] != "Done"):
	time.sleep(10)
	result = runCMD(rawCMD)
	resList = result.split("  ")
	if(thirds == 3):
		print "Scan Status:\t", resList[1]
		thirds = 0
	else:	
		thirds = thirds + 1
"""
####################################################################
## Retrieving 
## Report   
####################################################################
"""

if(verbose):
	print "Task Complete, Retrieving Report: Report ID:", report_ID
else:
	print "Task Complete: Retrieving Report"
rawCMD = "omp --get-report " + report_ID + " --format " + format_ID
res = runCMD(rawCMD)
try:
	f = open('/tmp/openvas_result.txt', 'w')
	f.write(res)
	f.close()
except IOError:
	print "Error: file openvas_result.txt could not be opened."

"""
####################################################################
## Removing 
## Target, Task   
####################################################################
"""

if(verbose):
	print "Removing Task:", task_ID, "Target:", target_ID
else:
	print "Removing Task, target"
rawCMD = "omp --xml=\"<delete_task task_id='" + task_ID + "'/>\"" #omp --xml="<delete_task task_id='267a3405-e84a-47da-97b2-5fa0d2e8995e'/>"
result = runCMD(rawCMD)

rawCMD = "omp --xml=\"<delete_target target_id='" + target_ID + "'/>\"" #omp --xml="<delete_target target_id='3797e9b3-2724-4e7c-a979-729c73fa13eb'/>"
result = runCMD(rawCMD)

print "Done"