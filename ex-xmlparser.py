#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4  smartindent

#-----------------------config-------------------------#

from etc.config import *

#---------------------prog start------------------------#

#transforming the original FireEye mail into a parsable xml file
formating = standard_input
w = parsed_xml
formated = re.sub("(?s).*?(\<\?xml version=)", "\\1", formating, 1)  #deleting all chars before the "<?xml version=" string
formated2 = formated.split('</alerts>', 1)[0] + '</alerts>'          #Delete everything after the </alerts> tag

#Delete XML Namespace value 
delns = re.sub(r'\sxmlns="[^"]+"', '', formated2, count=1)	     #deleting Namespaces (sxmnls value)
w.write(delns)
w.close()

#Writing mail head addresses, subject, and first body line 
w = open(mail_file,'w')
w.write(mail_atama) 

#PARSING START
with open(debug_folder + printdate  + '-formated.xml','r') as p:
    try:
        tree =  ET.parse(p)
        root = tree.getroot()
    except:
        logger.critical( 'Parsing failed: ↓↓ something went wrong with this xml file ↓↓ ')
        logger.critical( debug_folder + printdate  + '-formated.xml' )
        sys.exit()

# Fetching date (.text value in occured tag), convert it to server localtime and adding timezone
    if root.find('.//occurred') != None:
        date_ = root.find('.//occurred').text
        try:
            test_strip = re.search(r'\+\d+\d+\:\d+\d+', date_)
        except:
            test_strip = None
        local_timezone = tzlocal.get_localzone()
        if test_strip != None:
            try:
                strip_ = re.sub(r'\+\d+\d+\:\d+\d+', 'Z', date_, count=1)
            except:
                strip_ = None
        else:
            try:    
                strip_ = re.sub(r'\+\d+\d+', 'Z', date_, count=1)
            except:
                strip_ = None
        try:
            strpdate = datetime.strptime(strip_, '%Y-%m-%dT%H:%M:%SZ')
        except:
            try:
                strpdate = datetime.strptime(strip_, '%Y-%m-%d %H:%M:%SZ')
            except:
                strpdate = None
        if strpdate != None:
            convert = strpdate.replace(tzinfo=pytz.utc).astimezone(local_timezone)
            convert = str(convert)
            convert = convert.split("+", 1)[0]
            strp_convert = datetime.strptime(convert, '%Y-%m-%d %H:%M:%S')
            mail_format = datetime.strftime(strp_convert, '%a, %d %b %Y %H:%M:%S')
            simple_timezone = time.strftime('%z')
            w.write("Date: " + mail_format + " " + simple_timezone + "\n")
        else:
            w.write("Date: " + error_5)
    else:
        w.write("Date: " + error_5)

# Fetching ID (Child in alert tag)
    if root.find('.//alert') != None:
        alert_get = root.find('.//alert')
        if alert_get.get('id') != None:
            alertid_ = alert_get.get('id') 
            w.write("Id: " +  alertid_ + "\n")
        else:
            w.write("Id: " + error)
    else:
        w.write("Id: " + error)

# Fetching severity (Child in alert tag)
    if alert_get.get('severity') != None:
        sev_ = alert_get.get('severity')
        if sev_ == 'majr':
            sev_ = 'Major'
        if sev_ == 'crit':
            sev_ = 'Critical'
        w.write("Severity: " + sev_ + "\n")
    else:
        w.write("Severity: " + error)

# Fetching MID (child in smtp-message tag)
    if root.find('.//smtp-message') != None:
        get_smtpm = root.find('.//smtp-message')
        if get_smtpm.get('id') != None:
            mid_ = get_smtpm.get('id')
            w.write("MID: " + mid_ + "\n")
        else:
            w.write("MID: " + error)
    else:
        w.write("MID: " + error)

# Fetching from (part of .text value in smtp-header tag)
    if root.find('.//smtp-header') != None:
        from_ = root.find('.//smtp-header').text
        get_from = re.compile('header.from=(.*);')
        try:
            get_value = str(get_from.findall(from_))
        except:
            get_value = None
        if get_value == "[]":
            get_from = re.compile('From:(.*)\n')
            get_value = str(get_from.findall(from_))
            if get_value != "[]":
                clean_value = str(re.search('<(.*)>', get_value).group(1))
                w.write("From: " + clean_value + "\n")
            else:
                w.write("From: \n")
        else:
            try:
                replication = get_value.split(",")[0]
                clean_value = replication.replace('\'','').replace('[','').replace(']','') 
                w.write("From: " + clean_value + "\n") 
            except:
                w.write("From: \n")
    else:
        w.write("From: " + error)

# Fetching to (.text value in smtp-to tag)
    if root.find('.//smtp-to') != None:
        to_ = root.find('.//smtp-to').text
        try:
            w.write("To: " + to_ + "\n")
        except:
            w.write("To: \n")
    else:
        w.write("To: " + error)

# Fetching subject (.text value in subject tag)
    if root.find('.//subject') != None:
        sub_ = root.find('.//subject').text
        try:
            w.write("Subject: " + sub_ + "\n")
        except:
            w.write("Subject: " + error_4)
    else:
        w.write("Subject: " + error_4)

#def get_url function
    def get_url():
        if root.find('.//url') != None:
            url_and_header = root.find('.//url')
            try:    
                w.write("Malicious URL/MD5sum/header: " + url_and_header.text + "\n")
            except:
                w.write("Malicious URL/MD5sum/header: " + error_2)
        else:
            w.write("Malicious URL/MD5sum/header: " + error_2)

# Fetching URL/MD5sum/header 
    if root.find('.//malware-detected') != None:
        for mlw in root.find('.//malware-detected'):
            if mlw.find('.//original') != None:
                malware_name = mlw.find('.//original').text
	    else:
                malware_name = error_3
            md5_sum = mlw.find('.//md5sum')
        if md5_sum != None:
            try:
                w.write('Malicious URL/MD5sum/header: file://' + malware_name + "(" + md5_sum.text + ")\n")
            except :
                get_url()
        else: 
            get_url()
    else:
        get_url()

# Fetching CnC Address (.text value in smtp-to tag)
    if root.find('.//cnc-services') != None:
        def get_cnc():
            results = []
            for cnc in root.find('.//cnc-services'):
                if cnc.find('.//address') != None:
                    results.append(cnc.find('.//address').text)
                else:
                    w.write("CnC Address: " + error_2)
                    break
            return results
        kill_duplicate = list(set(get_cnc()))
        for item in kill_duplicate:
            try:
                w.write("CnC Address: " + item + "\n")
            except:
                w.write("CnC Address: " + error_2)
    else:
        w.write("CnC Address: " + error_2)


# writing the rest of the mail

w.write("\n" + body)
w.write(standard_input)
w.close()

#convert LF into CRLF, utf-8 to iso-2022-jp
with open(mail_file,'r') as r:
    data = r.read().decode("utf-8", "ignore")
    temp = re.sub(u"\r(?!\n)|(?<!\r)\n", "\r\n", data).encode("iso-2022-jp", "ignore")

with open(mail_file,'w') as w:
    w.write(temp)

logger.info('program has successfully ran, will now send the ' + tmp_folder + printdate + '.parsedMail file as mail.')

#sending the *.Parsedfile by mail via the sendmail binary
send_mail = "/usr/sbin/sendmail " + to_addr + " " + bcc_addr + " < " +  mail_file
e = None 
try:
    subprocess.check_output(send_mail, shell=True)
except subprocess.CalledProcessError as e:
    logger.critical(tmp_folder + printdate + '.parsedMail ↓↓ something went wrong with /usr/sbin/sendmail: ↓↓ ')
    logger.error(e)
if e == None: 
    logger.info('/usr/sbin/sendmail has successfully ran, if the mail didnt reach the desired destination please check /var/log/mail.log')

#    logger.info( tmp_folder + printdate + '.parsedMail: something went wrong with /var/log/sendmail ')
#---------------------prog end------------------------#


#----------------------debug--------------------------#

#show xml tree of the last sent mail (Uncomment the line below for debuging purpose)

with open(debug_folder + 'xml_tree.txt','w') as w:
    for child in root.iter():
        doc = child.tag, child.attrib, child.text
        print >> w, doc
