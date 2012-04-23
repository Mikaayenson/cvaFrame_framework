AutoVAS Readme
Andre Guerlain

Module:
AutoVAS


Description:
The AutoVAS module is a python script designed specifically to automatically runs an OpenVAS scan on a given target IP.  The script automatically retrieves a report of the scan results within the tmp directory.  This script can be run as a stand-alone script or as part of the CVA framework for which it was developed.  The CVAframe script calls the AutoVAS script for each different target it is given.


Disclaimer:  This code has the potential to be used for malicious purposes, due to it's ability to quickly identify security risks on remote machines.

Installation

Usage

Arguments

Known Bugs



Author:				Andre Guerlain
Date:				April 18th, 2012
Project ID:			Vulnerability Assessment Within the Cloud
Programming Language:		Python 2.6
OS/Hardware dependencies:	Linux distribution with Python and OpenVAS properly installed.  Information regarding installation of OpenVAS can be found at their site, http://www.openvas.org/install-packages.html.  


Disclaimer:  			This code has the potential to be used for malicious purposes, due to it's ability to quickly identify security risks on remote machines.  It was designed to be used as a means for preventing attacks.  The responsibility for any malicious or illegal use lies solely on the person using the code.  Furthermore, there is no guarantee of fitness for any specific purpose and this code is run at the discretion of the user.


Problem Description:		This script creates and runs a task within OpenVAS on a given target machine.


Overall Design:			This module is written strictly as a script, without a main function, along with supporting functions. 		


Program Assumptions 
      and Restrictions:		OpenVAS must be properly installed on the machine along with python 2.6 or later.


Interfaces:			how the program interacts with users, data or programs
	User
		The user must enter an ip address or range of addresses, along with a scan id.  The ip address must be in proper IPv4 format.  The scan id is an integer between 1-4 inclusive.  OpenVAS has four default types of scans each represented by a different number,
1 Full and fast,
2 Full and fast ultimate,
3 Full and very deep, and
4 Full and very deep ultimate.
The user can also enter an optional third flag, -v or --verbose.  There is also a -h or --help flag.
Examples:
	autovas 123.456.111.222 3 -v
	autovas -h
	autovas 123.111.222.333/24 2

	File/D-B
		The script automatically retrieves the results from the openvasmd(OpenVAS Manager) in text format and stores it into the /tmp/ directory on the machine.


Implementation Details:
	Algorithm		The script has a simple algorithm, going through the necessary steps to run an OpenVAS scan from the CLI.  It creates the target and makes a task to scan it.  Then the script starts the task.  Once the task has been started the script waits until the scan has completed.  Then the scan report can be retrieved from the openvasmd and stored in the tmp directory on the local machine.  Afterwards the script cleans up by deleting the target and task.  They are deleted because in order to run properly each time the script must create the target and task in order to use the resulting information later in the script.


How to build the program:	
	If OpenVAS is not running, but properly installed as described on their website-
		run the following commands to start up these components if they are not yet running,
		$sudo openvassd
		$sudo openvasmd
		$sudo openvasad
		$(optional)sudo gsad --http-only
		$python autovas.py <target ip> <scan id>
	These commands start up all of the different components of OpenVAS which are already running if you just installed OpenVAS.  The gsad is the Greenbone security assistant, which has both a GUI on the local host as well as a web application GUI which can be accessed remotely.  Neither of these are necessary to properly run this module, however it can be helpful for users who are less experienced with the OMP command line interface(CLI).  More detail about greenbone can be found on their website or by $man gsad.
	If OpenVAS is already running,
		run the following commands,
		$python autovas.py <target ip> <scan id>


Known Issues:
	Stopping the script prematurely:
		If the script is stopped prematurely, it may not run properly during subsequent calls on the same target.  It no longer runs properly because the target and or task created during the incomplete run have not been deleted.  There is a way to manually fix this using the following OMP commands:
			$omp --get-targets
			$omp --get-tasks
			$omp --pretty-print --xml<>

		To remove the task, first use the $omp --get-task command.  You should get a result looking like:
			5edd9f65-5dd7-49e9-9a74-30f00313608b  Done  temp
		The first part of this line is the task_id, the second is the state of the scan, and the third is the name.  All of the tasks created by this script are named temp and are normally deleted upon completion.  To manually delete the example task above, you would run $omp --pretty-print --xml="<delete_task task_id='5edd9f65-5dd7-49e9-9a74-30f00313608b'/>".  Be sure to use the correct corresponding task_id.

		To remove the target, first use the $omp --get-targets command.  You should get a result looking like:
			b493b7a8-7489-11df-a3ec-002264764cea  Localhost
			a7eb1c4b-c8e4-4e0d-b948-52ff5c5f65b3  Test...
		There should be no target for the machine you are trying to scan with the AutoVAS code.  This command does not give the information such as which ip the target is associated with, but   There should be a target for localhost, which should not be deleted.  The example target can be deleted by using the following command, $omp --pretty-print --xml="<delete_target target_id='a7eb1c4b-c8e4-4e0d-b948-52ff5c5f65b3'/>".
	
	For more information regarding OMP commands, use the $omp -? command.  For more information regarding the use of XML code within OMP commands go to http://www.openvas.org/omp-2-0.html.  If you do find an issue, you may contact rdaemon5@gmail.com.


Program Source:			autovas.py


Additional Files:		results.txt is created within the tmp directory on the local machine each time the module is run.


References:			Many websites are useful for understanding OpenVAS and this module script.  Some that are particularly helpful are,
				http://www.openvas.org/
				http://www.greenbone.net/technology/openvas.html
				http://www.python.org/




