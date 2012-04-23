#!/usr/bin/python
import os,sys,timeit
from time import time,sleep
start_pg = time()

print "Welcome to the test file\n"

os.system("echo 'alright alright alright....' | wall")
sleep(2.8)
end_pg = time()

print "Your script took %s seconds" % (end_pg - start_pg) 