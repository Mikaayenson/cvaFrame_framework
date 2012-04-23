#!/usr/bin/python 
import sys, os, subprocess

#########################################################
# Author: Mika Ayenson
# Title: rootkit
#
########################################################

#TODO
#finish help

#Global Variables
address = ""   #for the ip address of machines to exploit
verbose = False #to set the verbose variable 
vulnsf = "rootkitsfound" #the name of outfile

#help function will list modules
def help_cmd():
    print "\nUsage: python rootkit.py [args]\n"
    print "DESCRIPTION:"
    print "\tThe rootkit is developed as an opensource tool that allows cloud administrators to"
    print "\tto test their dormant images for rootkits. This tool is originally designed to work"
    print "\talong side the cvaFrame framework. See the mika ayenson github."
    print "\tAs alwyas, please use this tool wisely and its modules wisely."
    print "Args:"
    print "Examples:"
    print "\tpython rootkit.py -v"
    print "\tpython rootkit.py -h"
    print "AUTHOR:"
    print "\tWritten by Mika D. Ayenson\n"
    print "REPORTING BUGS"
    print "\tThis is an open source project, but you can report rootkit.py bugs to rdaemon5@gmail.com\n"
    print "DISCLAIMER"
    print "\tBy using this tool, you agree to use it in compliance to metsploit agreements."
    print "\tYou solely are responsible for any mishaps or legal binds you get in.\n"
                                                                                    
#validate Ip address
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
                          
#get special line arguments
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
                                                                  
#get args from command line
def getCmdArgs():
    if(len(sys.argv)) == 1:
        #default
        address = subprocess.Popen(["route | tail -1 | cut -d' ' -f1"],shell=True,stdout=subprocess.PIPE).communicate()[0].strip()
        address.wait()
        print "No ip was specified. Using default ip range " + address + "\n"
        print "Please wait while rootkit is in progress, this will take some time. You can also use '-v' verbose mode for more output. \n"
        #only ip address specified
    elif(len(sys.argv)) == 2:
        if(line_args(sys.argv[1])==True):
            print "Please wait while rootkit is in progress. You can also use '-v' verbose mode for more output. \n"
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
            vulnsf = sys.argv[3]
            line_args(sys.argv[2])
            line_args(sys.argv[1])
            print "Using: '"+vulnsf+"' as the name of your output file\n"
        else:
            print "Try: 'python sploit.py -h'\n"
            sys.exit(1)
                                                                                                                                          
#gather os type
def getOSType(ipAddress):
    cmd = "nmap -A "+ipAddress 
    nmap = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
    while True:
        line = nmap.stdout.readline()
        if line != '':
            if "OS:" in line:
                print "Rootkit: ",line
                return line
        else:
            break
    nmap.wait()
    return "Unknown"

#mount correct os to backtrack 
def mountOS(line,address):
    #add user
    #adduser root fuse
    
    cmd = "sshfs "+address+":/ mountplace/"
    if "Mac" in line or "Apple" in line or "Darwin" in line or "iOS" in line:
        print "Mac"
        #mount
        sshfs = subprocess.Popen(cmd,shell=True)
        sshfs.wait()
    elif "Linux" in line:
        print "Linux"
        #mount
        sshfs = subprocess.Popen(cmd,shell=True)
        sshfs.wait()
    elif "Windows" in line:
        print "Windows"
        #mount
        cmd = "sshfs "+address+":C:\ mountplace/"
        sshfs = subprocess.Popen(cmd,shell=True)
        sshfs.wait()
    elif "Unix" in line:
        print "Unix"
        #mount
        sshfs = subprocess.Popen(cmd,shell=True)
        sshfs.wait()
    else:
        print "Nmap can't determine os type. Exiting now."
        sys.exit(1)

#unmount the operating system         
def unmountOS():
    print "unmounting target"    
    cmd = "fusermount -u /root/mountplace/"
    sshfs = subprocess.Popen(cmd,shell=True)
    
#run the chkrootkit framework     
def chkrootkit():
    global vulnsf
    outfile = open(vulnsf,'w')
    print "running the chkrootkit framework"
    cmd = "sh /pentest/forensics/chkrootkit/chkrootkit -r /root/mountplace/"
    sshfs = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
    while True:
        line = sshfs.stdout.readline()
        if line != '':
            print "rootkit: ",line
            if "INFECTED" in line or "Vulnerable" in line:
                outfile.write("rootkit: "+line)
        else:
            break
        sshfs.wait()
        outfile.close()
                                            
#main
def main():
    print "Welcome to rootkit\n"
    getCmdArgs()
    global address
    OS = getOSType(address)
    mountOS(OS,address)
    chkrootkit()
    print "You can now view the file '"+vulnsf+"' \n"
    unmountOS()
    
if __name__ == "__main__":
    main()
    print "Fin."
    sys.exit(1)