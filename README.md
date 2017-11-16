# FireEye EX Mail Parser

This script goal is to:

- Monitor incoming mails in given directory via .procmailrc.
- Kick the ex-xmlparser.py script when FireEye EX incident mail reach the inbox.
- ex-xmlparser.py will parse FireEye EX raw mail.
- Store parsed information.
- Generate a custom mail template and write the parsed data into it.
- Send the custom mail.

## Prerequisite

- Linux / Unix kernel
- postfix
- procmail
- sendmail
- Python 2.7
- pip
- pip install tzlocal
- pip install pytz


## Usage

### 1 - configuring procmail and postfix
- please refer to your distribution documention for configuring /etc/postfix/main.cf and other .conf files

### 2 - configuring etc/config.py 
- set the USERFOLDER in file_handler
- set the USERFOLDER in conf_folder 
- set the USERFOLDER in tmp_handler
- set the USERFOLDER in debug_handler
- set the destinaton addresses in to_addr
- set the invisible CC addresses in bcc_addr 


### 3 - configuring .procmail.rc
- Set the USERFOLDER below ^Subject: Malware.*Object detected:


### 4 - Parsing the json file to a human/splunk friendly file

- parse.py 2017-10-XX-website-1.json (Can only parse json file created by the first script export_incap.py)
- The output will a txt file, Parsing events into incidents ( One event can contain multiple incidents)

### 4 - Sample files

- You can find one .json sample which is the Output of export_incap.py You can parse it with parsed.py.

- You can find 2017-10-XX-website-1.txt, which is the output of parsed.py.
