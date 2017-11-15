# -*- coding: utf-8 -*-

import time
from datetime import datetime
import tzlocal # pip install tzlocal
import pytz    # pip install pytz
import sys
import xml.etree.ElementTree as ET
import re
import os
import subprocess
import logging
from logging.handlers import RotatingFileHandler

reload(sys)
sys.setdefaultencoding('utf8')

#-------CONFIGURATION START--------#

#logging
class StreamToLogger(object):
   def __init__(self, logger, log_level=logging.INFO):
      self.logger = logger
      self.log_level = log_level
      self.linebuf = ''

   def write(self, buf):
      for line in buf.rstrip().splitlines():
         self.logger.log(self.log_level, line.rstrip())

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
file_handler = RotatingFileHandler('/home/USERFOLDER/log/ex-xmlparser.log', 'a', 10000000, 10) #writing into /var/log/xmlparser.log | rotate logfile when it reach 10 mo | maximum number of log files : 10
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

stdout_logger = logging.getLogger('STDOUT')
sl = StreamToLogger(stdout_logger, logging.INFO)
sys.stdout = sl

stderr_logger = logging.getLogger('STDERR')
sl = StreamToLogger(stderr_logger, logging.ERROR)
sys.stderr = sl

#Checking stdin
if sys.stdin.isatty() != False:
        logger.critical("ex-xmlparser.py(FireEye mail parser  script): Script exited, stdin is null, please open /home/USERFOLDER/procmail.log, and check the latest log")
        sys.exit()

#defining files,  and folder
conf_folder = "/home/USERFOLDER/etc/"
tmp_folder = "/home/USERFOLDER/tmp/"
debug_folder = "/home/USERFOLDER/debug/"
now = datetime.now()
printdate = now.strftime("%Y-%m-%d_%Hh%Mm%S.%fs")                           #defining time for file creation
parsed_xml = open(debug_folder + printdate + '-formated.xml','w')           #defining the the xml file which will be parsed.
standard_input = sys.stdin.read()                                           #for procmail implementation (procmail pass the mail in stdin, not argv)
mail_file = (tmp_folder + printdate + '.parsedMail')                        #defining the final file which will be send via sendmail
body = open(conf_folder + 'body.conf','r').read()
error = "N/A\n"
error_2 = "N/A\n"
error_3 = "N/A"
error_4 = "N/A\n"
error_5 = "N/A\n"
# /!\ PRODUCTION /!\ 
#email config
to_addr = "email_1@provider.com, email_2@provider.com, email_3@provider.com"
bcc_addr = "bcc@your_company.com"
mail_atama = open(conf_folder + 'atama.conf','r').read()                   
#/!\ PRODUCTION END /!\

# /!\ DEBUG /!\ 
#email config
#to_addr = "your_mail@your_company.com"        
#bcc_addr = ""                           
#mail_atama = open(conf_folder + 'test_atama.conf','r').read()
# /!\ DEBUG END /!\

#-------CONFIGURATION END--------#
