#!/usr/bin/python
import sys, os, subprocess, time, MySQLdb
from datetime import datetime
from time import time


#########################################################
# Author: Mika Ayenson
# Title: cvaFrame
#
# This script is used to run the modules sploit and 
# openvas.  This is the core to the cvaframework and 
# manages the images for the vulnerability assessment
#
########################################################


#TODO
# remove known hosts

#Global Variables
modules = ['sploit','openvas','test'] #later add modules rootkit, and virusScan
moduleVm = "" #contains the vm id of the image containing vulnerability assessment modules 
modulelist = []#contains a list of modules the user wants to run
openvasStartup = False
db_address = "" #the address of the database to be run
 
#database credenials
user = ""
password = ""
dbname = ""


#help function will list modules
def help_cmd():
    print "\nUsage: python cvaframe.py [module]\n"
    print "DESCRIPTION:"
    print "\tThe cvaFrame is developed as an opensource framework that allows cloud administrators to"
    print "\tto test their dormant images for vulnerabilites and exploits. This tool should be"
    print "\tused as a stepping stone towards providing security in the cloud and automated feedback"
    print "\tto the administrator. Please use this tool wisely and its modules wisely."
    print "MODULES:"
    print "\tsploit: \tTest exploitations by attemping to open sessions against a target"
    print "\topenvas: \tScan for vulnerabilities throughout the entire image"
    print "\ttest: \tQuick test to ensure setup is corrent."
    print "Examples:"
    print "\tpython cvaframe.py sploit"
    print "\tpython cvaframe.py sploit openvas"
    print "AUTHOR:"
    print "\tWritten by Mika D. Ayenson\n"
    print "REPORTING BUGS"
    print "\tThis is an open source project, but you can report cvaframe.py buds to rdaemon5@gmail.com\n"
    print "DISCLAIMER"
    print "\tBy using this tool, you agree to use it in compliance to metsploit agreements."
    print "\tYou solely are responsible for any mishaps or legal binds you get in.\n"

#set environment variables
def setEnvVar():
    #get environment variables from command line
    URL = False
    ACCESS = False
    SECRET = False
    try:
        f = open(".config",'r')
        for lines in f:
            if "EC2_URL" in lines:
                temp = lines.split('=')
                EC2_URL = temp[1].strip()
                URL = True
            elif "EC2_ACCESS_KEY" in lines:
                temp = lines.split('=')
                EC2_ACCESS_KEY = temp[1].strip()
                ACCESS = True
            elif "EC2_SECRET_KEY" in lines:
                temp = lines.split('=')
                EC2_SECRET_KEY = temp[1].strip()
                SECRET = True
        f.close()
        if URL and ACCESS and SECRET:
            os.putenv("EC2_URL",EC2_URL)
            os.putenv("EC2_ACCESS_KEY",EC2_ACCESS_KEY)
            os.putenv("EC2_SECRET_KEY",EC2_SECRET_KEY)
    except IOError as e:
        print "Can't locate your config file. Please place you '.config' file with your EC2 account information in this directory."
        sys.exit(1)

#get the database credentials        
def getDBcreds():
    global db_address
    global user
    global password
    global dbname
    db_address = raw_input("Please enter the ip address of the database you would like to use.")
    print "Thank you"
    user = raw_input("Please enter the username of the database you would like to use.")
    print "Thank you"
    password = raw_input("Please enter the password of the database you would like to use.")
    print "Thank you"
    dbname = raw_input("Please enter the database name of database you would like to use.")
    print "Thank you" 
    
    confirm = raw_input("Are you sure you have entered the correct login information?  If it is not correct, your database will not be populated.  y or n")
    if confirm == "y" or confirm == "Y":
        pass
    else:
        print "Please run the cvaframe again with the correct login credentials."
        sys.exit(1)
    
#get the modules the security administrator would like to run        
def getModules():
    for args in range(1,len(sys.argv)):
        if sys.argv[args] in modules:
            modulelist.append(sys.argv[args])
        else:
            print "Sorry, the CVA framwork does not recognize the module '" + sys.argv[args] + "'. Exiting now. Try 'python cvaframe.py -h' for a list of modules."
            if (len(sys.argv)==2):
                sys.exit(1)
            else:
                print "Will not run module '"+sys.argv[args]+"'. Try 'python cvaframe.py -h' for a list of modules."
        
#collect the module/command line arguements to run
def parseArgs():
    if (len(sys.argv)==2):
        if sys.argv[1] == "-h" or sys.argv[1] == "--help":
            help_cmd()
            sys.exit(1)
        elif (len(sys.argv) > 1):
            getModules()
    elif (len(sys.argv)>1):
        getModules()
    else:
        print "Please enter a module to run"
        sys.exit(1)
            
#collect all the image ids
def getImageIds():
    modulevm = raw_input("Please enter the id of the image containing vulnerability assessment modules: ")
    imageIdList = []
    #call a subprocess to open ec2 commands
    proc = subprocess.Popen("euca-describe-images",stdout=subprocess.PIPE)
    while True:
        temp = []
        line = proc.stdout.readline()
        if line != '':
            if "deregistered" in line:
                pass
            else:
                temp = line.split()
                imageIdList.append(temp[1])
        else:
            break
    if modulevm in imageIdList:
        global moduleVm
        moduleVm = modulevm
        imageIdList.pop(imageIdList.index(modulevm))
    else:
        print "Sorry you have not entered a valid id of the image containing vulnerability assessment modules. Exiting now."
        sys.exit(1)
    return imageIdList

#virtual machine functions
def startVM(image_id):
    proc = subprocess.Popen(["euca-run-instances",image_id],stdout=subprocess.PIPE)
    while True:
        line = proc.stdout.readline()
        if line!='':
            temp = line.split()
            if temp[0].strip()=="INSTANCE":
                print "Starting instance: " + temp[1].strip()
                return temp[1].strip() +" "+ temp[3].strip() #address and instance
            else:
                pass
        else:
            break
     
#close the virtual image instance        
def closeVM(image_id):
    proc = subprocess.Popen(["euca-terminate-instances",image_id])
    print "Closing instance: " + image_id +"\n"
    status = proc.poll()

#check the status of the virtual machine instance    
def checkStatus(instance_id):
    proc = subprocess.Popen("euca-describe-instances",stdout=subprocess.PIPE)
    while True:
        line = proc.stdout.readline()
        if line!= '':
            if instance_id in line:
                temp = line.split()
                if temp[0].strip()=="INSTANCE":
                    status = temp[5].strip()
                    print "Status: " + status
                    if status == "shutting-down":
                        closeVM(instance_id)
                    return status
                else:
                    pass
            else:
                pass
        else:
            break
    pstatus = proc.poll()

#pulls the scan id from the database to match scans correctly to the database with modules    
def getScanID(cursor):
    cursor.execute("Select max(scan_id) from scans")
    str = cursor.fetchone()[0]
    if str is None:
        cursor.execute("alter table scans auto_increment=0")
        str = 1
    else:
        str += 1
    return str
                                                                        
#pulls the file from the backtrack instance and places it on the local cvaframe temporarily
def getFile(filename,backtrack):
    process = subprocess.Popen("scp root@"+backtrack+":/tmp/"+filename+" /tmp", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = process.communicate()[0]
    process.wait()
    print "getfile: ",filename, output
    return filename
        
#file to database section 
def db_sploit(vulns,cursor):
    print "Populating the database with sploit report."
    scanID = str(getScanID(cursor))
    f = open(vulns,'r')
    #get scanid from db
    for lines in f:
        temp = lines.split()
        HOST = temp[7].strip()
        refs = temp[9].split('=')
        refs2 = refs[1].split(',')
        CVE = refs2[0].split()[0]
        OSVDB = refs2[1].split()[0]
        BID = refs2[2].split()[0]
        NAME = temp[8].strip()
        SCAN_ID = scanID
        print HOST,CVE,OSVDB,BID,NAME,SCAN_ID
        status = cursor.execute("INSERT INTO sploit(host,cve,osvdb,bid,name,scan_id) VALUES( \""+HOST+"\",\""+CVE+"\",\""+OSVDB+"\",\""+BID+"\",\""+NAME+"\","+SCAN_ID+")")
        print status
    f.close()
                                                                                           
#openvas populate database    
def db_openvas(vulns, cursor):
    print "Populating the database with the openvas report."
    first = False
    issue = "Issue\n"
    attList = [""]*6
    scan_id = str(getScanID(cursor))
    f = open(vulns, 'r')
    for line in f:
        if line == issue and first:
            cursor.execute("INSERT INTO autovas (scan_id, nvt, oid, threat, port, cve, bid) VALUES (" +scan_id+ ", \"" + attList[0] +"\", \""+ attList[1] +"\", \""+ attList[2] +"\", \""+ attList[3] +"\", \""+ attList[4] +"\", \""+  attList[5] +"\")")
            attList = [""]*6
        elif line == issue and not first:
            first = True
        elif "NVT:" in line:
            attList[0] = line[8:-1]
        elif "OID:" in line:
            attList[1] = line[8:-1]
        elif "Threat:" in line:
            attList[2] = line[8:-1]
        elif "Port:" in line:
            attList[3] = line[8:-1]
        elif "CVE :" in line:
            attList[4] = line[6:-1]
        elif "BID :" in line:
            attList[5] = line[6:-1]
    
    if first == True:
        cursor.execute("INSERT INTO autovas (scan_id, nvt, oid, threat, port, cve, bid) VALUES (" +scan_id+ ", \"" + attList[0] +"\", \""+ attList[1] +"\", \""+ attList[2] +"\", \""+ attList[3] +"\", \""+ attList[4] +"\", \""+  attList[5] +"\")")
    f.close()
                          
#populate the database with scan information    
def db_scan(cursor,items,startdate,enddate):
    print "Populating the database with scan info."
    #items is the image id
    
    status = cursor.execute("INSERT INTO scans (image_id, startTime, endTime) VALUES (\"" +items+ "\",\"" +startdate+ "\",\"" +enddate+ "\")")
    print status
    
#puls information from a file and dumps it into the database    
def fileToDB(outfile,items,startdate,enddate):
    print "Populating the databse now =)"
    #connect to database
    global db_address
    global user
    global password
    global dbname
    conn = MySQLdb.connect (db_address,user,password,dbname);
    cursor = conn.cursor()

    if "sploit" in outfile:
        db_sploit(outfile, cursor)
    elif "openvas" in outfile:
        db_openvas(outfile, cursor)
    else:
        print "Could not file the file '"+outfile+"'. Please check the filename."
   
    db_scan(cursor,items,startdate,enddate)    
    conn.close()
    #disconnect the database    

#run the sploit module    
def sploit(target, date, backtrack,items): #run sploit module
    print "In sploit module"
    
    process = subprocess.Popen("ssh root@"+backtrack +" python /root/sploit.py "+ target +" /tmp/sploit_"+date ,shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,stderr = process.communicate()
    status = process.wait()
    print output
    
    enddate = datetime.now().strftime("%Y%m%d%H%M%S")
    
    output = getFile("sploit_"+date,backtrack)
    fileToDB("/tmp/"+output,items,date,enddate)    
    return output

#run the autoVAS module
def openvas(target, date, backtrack,items): #run sploit module
    global openvasStartup
	
    print "In openvas module"

    while True:
        if openvasStartup != True:
            process = subprocess.Popen("ssh root@"+ backtrack +" sh /root/startup.sh", shell=True, stdout=None, stderr=None)
            while True:
                process = subprocess.Popen("ssh root@"+ backtrack +" omp -O", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                retval = process.communicate()[1]
                if "socket" in retval.strip():
                    print "waiting for openvasmd"
                else:
                    print "In openvas module"
                    break
            openvasStartup = True
            break
        else:
            break
        
    process = subprocess.Popen("ssh root@"+ backtrack +" python /root/autoVAS.py " + target + " 2 -v", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = process.communicate()[0]
    process.wait()
    print output
    
    enddate = datetime.now().strftime("%Y%m%d%H%M%S")
    
    output = getFile("openvas_result.txt",backtrack)
    #call subprocess to mv file to a filename with the date appeneded
    os.system("cp /tmp/openvas_result.txt /tmp/openvas_result_"+date+".txt")
    fileToDB("/tmp/openvas_result_"+date+".txt",items,date, enddate)
    return "openvas_result.txt"

#send the command to run the module 
def sendCmds(instance,target,backtrack,items):

    print instance, target,backtrack
   # backtrack = "192.168.143.190" #used for testing
    date = datetime.now().strftime("%Y%m%d%H%M%S")
    print "Exploiting instance: "+instance +" at ip address: " + target
    	
    #for item in modulelist  #this will iterate over all the modules the user specified
    for item in modulelist:
        if item == "sploit":
    		sploit(target, date, backtrack,items)
    	elif item == "openvas":
    		openvas(target, date ,backtrack,items)
    	else:
            process =  subprocess.Popen("ssh root@"+backtrack +" python /root/testfile.py",shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            output,stderr = process.communicate()
            print output

            global db_address
            global user
            global password
            global dbname
            con = MySQLdb.connect (db_address,user,password,dbname);
            cur = con.cursor()
            
            db_scan(cur,"ami-00000143","before","after")
            con.close()
            
#wait for the instance of the image with modules to start the sshserver            
def checkSSH(backtrack):
    while True:
        cmd =  "ssh root@"+backtrack+" 'echo 2>&1' && echo root@"+backtrack+" OK || echo root@"+backtrack+" NOK"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        retVal = process.communicate()[0]
        if "NOK" in retVal:
            print "waiting for the ssh server to start"
        elif "OK" in retVal:
            print "ssh is up and running on backtrack"
            break
        else:
            print "openssh server will not run.  Please try to run the cvascript again."
            sys.exit(1)
    
#start the party.            
def exploit():
   
    ids = getImageIds() #list of targets
    
    #start modulevm
    global moduleVm
    retModule = startVM(moduleVm)#moduleVm
    tempMd = retModule.split()
    moduleInstance  = tempMd[0].strip() #instance of backtrack
    backtrack = tempMd[1].strip() #ip address of backtrack
    print "Starting Module VM: " + moduleVm
    while checkStatus(moduleInstance)=="pending":
        pass

    
    #check ssh running
    checkSSH(backtrack)
    
    for items in ids:
        #while image id in list 
        print "Exploiting target image: " + items #ami-00000143 target     
   
        #start first vm from image id x
        retval = startVM(items) #ami-00000143 target
        temp = retval.split() #startVm return value
        instance = temp[0].strip() #image id of the target
        target = temp[1].strip() #ip address of the target

        print "Please wait while the target instance is loaded..."
        #before exploit check status
        while checkStatus(instance) =="pending":
            pass
       
        #run module
        sendCmds(instance,target,backtrack,items) #this is the ip of the target 
   
        #close vm
        closeVM(instance)
        while checkStatus(instance)=="shutting-down":
            print "shutting down instance: "+instance
            closeVM(instance)
            pass
       
    #close modulevm
    closeVM(moduleInstance)

#main
def main():
    print "\n\n*************************************************************"
    print "** Welcome to the cvaFrame cloud vulnerability assessment. **"
    print "*************************************************************\n\n"

    #print "Running Main"
    start_pg = time()
    parseArgs()
    setEnvVar()
    getDBcreds()
    #db_image_id = "ami-00000168"
    global db_address
    #db_address=startVM(db_image_id).split()[1]         #start the database  
    exploit()             
    #closeVM(db_image_id)         #close the database
    end_pg = time()
    print "The CVA took %s seconds" % (end_pg - start_pg)

if __name__ == "__main__":
    main()
    print "Fin. You can find your files in your /tmp/ directory."
    #os.system(cat file|mail -s cvaFrame report email)
    post = raw_input("waiting for admin to close...type any button.")
    sys.exit(1)