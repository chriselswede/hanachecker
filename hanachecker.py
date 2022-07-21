# -*- coding: utf-8 -*-
from datetime import datetime
import sys, time, os, subprocess
import zipfile

def printHelp():
    print("                                                                                                                                                    ")    
    print("DESCRIPTION:                                                                                                                                        ")
    print(' The HANA Checker executes SQL: "HANA_Configuration_MiniChecks" (See SAP Note 1969700). For every "potential critical" mini-check,                  ')
    print(' i.e. where the column C has an X, it sends out an email to the email address specified for that particular mini-check. This can run "forever"      ')
    print(" with a specified interval. See also SAP Note 1999993.                                                                                              ")
    print("                                                                                                                                                    ")
    print("INPUT ARGUMENTS:                                                                                                                                    ")
    print("         *** MINI-CHECKS, PARAMETER-CHECKS and EMAILS mapping ***                                                                                   ")
    print(" -<CHID> mini-check to email address, if that particular mini-check specifed by the flag is potential critical an email is sent to the address      ")
    print("         specified by the value of the flag, e.g. -M0230 peter@ourcompany.com, then Peter will get an email if CHID 230 shows an X in C.            ")
    print(" -cg     mini-check groups, groupings of mini-checks with responsible email addresses associated, example:                                          ")
    print("         -cg M0001-M1500,peter@ourcompany.com,M1501-M3000,sara@ourcompany.com,S0100-S0200,chris@ourcompany.com                                      ")
    print(" -pe     parameter emails, a comma seperated list of emails that catches all parameter checks, default '' (not used)                                ")
    print("         Note: This only makes sense if HANA_Configuration_Parameters is included in the input, either with -mf, or -ct P                           ")
    print(" -se     sql emails, a comma seperated list of emails that catches all sql statements with recommendation in SAP Note 2000002, default '' (not used)")
    print("         Note: This only makes sense if HANA_SQL_SQLCache_TopLists is included in the input, either with -mf, or -ct R                              ")
    print(" -ee     error emails, a comma seperated list of emails that recieves the most important HANAChecker errors, default '' (not used)                  ")
    print(" -is     ignore check_why_set parameter, if this is true parameter with recommended value 'check why set' are ignored, default false                ")
    print(" -at     active threads, set MIN_ACTIVE_THREADS in modification section in the Call Stacks Minichecks, default '' (not used, i.e. 0.2)              ")
    print(" -abs    ABAP schema, to define the ABAP schema in case -ct A is used,                                 default '' (not used)                        ")
    print(" -ip     ignore dublicated parameter, parameters that are set to same value in different layers will only be mentioned once, default true           ")
    print(" -oe     one email [true/false], true: only one email is sent per email address, false: one email is sent per critical mini check, default: false   ")
    print(" -as     always send [true/false], true: all email addresses will be send at least a notification email, even if none of the mini-checks assigned   ")
    print("         to the emails were potential critical, default: false                                                                                      ")
    print(" -ca     catch all emails, the email addresses specified by the -ca flag recieve an email about each potential critical mini-check (also from       ")
    print("         parameter checks and SQL checks, if any), default: '' (not used)                                                                           ")
    print(" -ic     ignore checks, a list of mini-check CHIDs (seperated by commas) that should be ignored by the catch all emails (they will however          ")
    print("         still be included in the log files), default '' (not used)                                                                                 ")
    print(" -il     ignore list, a list of mini-check CHIDs (seperated by commas) that are ignored (i.e. not even in log files), default '' (not used)         ")
    print("         ----  HOST  ----                                                                                                                           ")
    print(" -vlh    virtual local host, if hanacleaner runs on a virtual host this can be specified, default: '' (physical host is assumed)                    ")
    print("         *** INPUT ***                                                                                                                              ")
    print(" -mf     full path(s) of a mini-check file(s)                                                                                                       ")
    print("         Example:  -mf /tmp/SQLStatements/HANA_Configuration_MiniChecks_1.00.102.01+.txt                                                            ")
    print("         Example:  -mf /tmp/SQLStatements/HANA_Configuration_MiniChecks_1.00.120+.txt,/tmp/SQLStatements/HANA_Security_MiniChecks.txt               ")
    print(" -zf     full path to SQLStatement.zip (cannot be used together with -mf and must be used together with -ct), default '' (not used)                 ")
    print("         Example:  -zf SQLStatements.zip  (if the zip file is located in same directory as hanachecker.py)                                          ")
    print(" -ct     check types, specifies what types of mini-checks to executes (must be used together with -zf), default '' (not used)                       ")
    print("         Example:  -ct M,I,S,T,P,C,R,A (in this example all possible mini-check types; mini, internal, security, trace, parameter, call stacks,     ")
    print("                                        SQL recommendations, and ABAP would be executed)                                                            ")
    print(" -ff     flag file(s), a comma seperated list of full paths to files that contain input flags, each flag in a new line, all lines in the file that  ")
    print("         do not start with a flag (a minus) are considered comments,                                                    default: '' (not used)      ")
    print("         *** OUTPUT ***                                                                                                                             ")
    print(" -od     output directory, full path of the folder where the log files will end up (if not exist it will be created),                               ")
    print("         default: '/tmp/hanachecker_output'                                                                                                         ")
    print(" -so     standard out switch, 1: write to std out, 0: do not write to std out, default:  1                                                          ")
    print(" -oc     output configuration [true/false], logs, in the emails send out if -as is set, all parameters set by the flags and where the flags were    ")
    print("         set, i.e. what flag file(one of the files listed in -ff) or if it was set via a flag specified on the command line, default = false        ")
    print("         *** EMAIL ***                                                                                                                              ")
    print("         Possibly there is no need for any -en* flag. This depends on the configuration of your email client. If you recieve en email from this     ")
    print('                             echo "Text in email" | mailx -s "subject" <your email address>                                                         ')
    print("         then there is no need for any -en* flag. Contact your Linux expert for more information.                                                   ")
    print(" -enc    email client, for example mail, mailx, mutt, ...,                                       default: mailx                                     ")
    print("         NOTE: If you want to use HANAChecker just to write log files, without sending emails, then specify this flag empty, -enc '', and provide a ")
    print("               dummy email address for the -ca flag  to write to file all potential critical mini-checks                                            ")
    print('         NOTE: For e.g. mailx to work you have to install the linux program "sendmail" and add something like DSsmtp.intra.ourcompany.com in the    ')
    print("               file sendmail.cf in /etc/mail/, see https://www.systutorials.com/5167/sending-email-using-mailx-in-linux-through-internal-smtp/      ")
    print(" -ens    sender's email, to explicitly specify sender's email address, this might not be needed,   default:    (configured sender's email used)     ")
    print("         This is the same as adding    -S from=<senders email address>     to the echo statement above                                              ")
    print(" -enm    mail server, to explicitly specify mail server, this might not be needed,                 default:    (configured mail server used)        ")
    print("         This is the same as adding    -S smtp=smtp://<email server>       to the echo statement above                                              ")
    print(" -en     depricated! email notification, <sender's email>,<mail server>   example: me@ourcompany.com,smtp.intra.ourcompany.com    Don't use!        ")
    print("         *** ADMIN ***                                                                                                                              ")
    print(" -hci    hana checker interval [days], number days that HANA Checker waits before it checks again, default: -1 (exits after 1 cycle)                ")
    print("         NOTE: Do NOT use if you run hanachecker in a cron job!                                                                                     ")
    print(" -ssl    turns on ssl certificate [true/false], makes it possible to use SAP HANA Checker despite SSL, default: false                               ")                 
    print(" -k      DB user key, this one has to be maintained in hdbuserstore, i.e. as <sid>adm do                                                            ")               
    print("         > hdbuserstore SET <DB USER KEY> <ENV> <USERNAME> <PASSWORD>                     , default: SYSTEMKEY                                      ")
    print("         It could also be a list of comma seperated userkeys (useful in MDC environments), e.g.: SYSTEMKEY,TENANT1KEY,TENANT2KEY                    ")
    print(" -dbs    DB key, this can be a list of databases accessed from the system defined by -k (-k can only be one key if -dbs is used)                    ")               
    print("         Note: Users with same name and password have to be maintained in all databases   , default: ''  (not used)                                 ")
    print("         Example:  -k PQLSYSDB -dbs SYSTEMDB,PQL                                                                                                    ")
    print("                                                                                                                                                    ")
    print("                                                                                                                                                    ")
    print(" EXAMPLE: The default mail client mailx is used                                                                                                     ")
    print(" python hanachecker.py -k T1KEY -zf SQLStatements.zip -ct M,S -M1142 chris@du.my,lena@du.my -M1165 per@du.my,lena@du.my -S0120 chris@du.my -as true -oe true ")
    print("                                                                                                                                                    ")
    print(" TODO: test                                                                                                                                         ")
    print("       CALL SYS.STATISTICSSERVER_SENDMAIL_DEV('SMTP',25,'emailfrom','emailto1,emailto2','Test mail from HANA system subject','Test body from HANA, body',?); ")
    print("                                                                                                                                                    ")
    print("AUTHOR: Christian Hansen                                                                                                                            ")
    print("                                                                                                                                                    ")
    print("                                                                                                                                                    ")
    os._exit(1)
    
def printDisclaimer():
    print("                                                                                                                                   ")    
    print("ANY USAGE OF HANACHECKER ASSUMES THAT YOU HAVE UNDERSTOOD AND AGREED THAT:                                                         ")
    print(" 1. HANAChecker is NOT SAP official software, so normal SAP support of HANAChecker cannot be assumed                               ")
    print(" 2. HANAChecker is open source                                                                                                     ") 
    print(' 3. HANAChecker is provided "as is"                                                                                                ')
    print(' 4. HANAChecker is to be used on "your own risk"                                                                                   ')
    print(" 5. HANAChecker is a one-man's hobby (developed, maintained and supported only during non-working hours)                           ")
    print(" 6  All HANAChecker documentations have to be read and understood before any usage:                                                ")
    print("     a) The .pdf file that can be downloaded at the bottom of SAP Note 1999993                                                     ")
    print("     c) All output from executing                                                                                                  ")
    print("                     python hanachecker.py --help                                                                                  ")
    print(" 7. HANAChecker is not providing any recommendations, all flags shown in the documentation (see point 6.) are only examples        ")
    os._exit(1)

############ GLOBAL VARIABLES ##############
chidMax = 9999
htmlSend = True

######################## DEFINE CLASSES ##################################

class EmailSender:
    def __init__(self, emailClient, senderEmail, mailServer):
        self.emailClient = emailClient
        self.senderEmail = senderEmail
        self.mailServer = mailServer
    def printEmailSender(self):
        print("Email Client: ", self.emailClient, "  Sender Email: ", self.senderEmail, "  Mail Server: ", self.mailServer) 

class MiniCheck: # //@audit-info MiniCheck
    def __init__(self, CHID, Area, Description, Host, Port, Count, ActiveThreads, LastOccurrence, Value, Expectation, C, SAPNote, TraceText):
        self.CHID = CHID
        self.Type = get_check_type(CHID)
        self.Number = get_check_number(CHID)
        self.Area = Area
        self.Description = Description
        self.Host = Host
        self.Port = Port
        self.Count = Count
        self.ActiveThreads = ActiveThreads
        self.LastOccurrence = LastOccurrence
        self.Value = Value
        self.Expectation = Expectation
        self.C = C
        self.SAPNote = SAPNote
        self.TraceText = TraceText
    def summary(self):
        if htmlSend:
            return self.htmlSummary()
        return self.minimalistSummary()
    def htmlSummary(self):
        return "<tr>"+"".join(["<td>{}</td>".format(v) for v in vars(self).values()])+"</tr>"
    def minimalistSummary(self):
        sum = "\nMini Check ID "+str(self.CHID)
        if self.Area:
            sum += "  Area: "+self.Area
        if self.Description:
            sum += "  Description: "+self.Description
        if self.Host:
            sum += "  Host: "+self.Host
        if self.Port:
            sum += "  Port: "+self.Port
        if self.Count:
            sum += "  Count: "+self.Count
        if self.ActiveThreads:
            sum += "  Active Threads: "+self.ActiveThreads
        if self.LastOccurrence:
            sum += "  LastOccurrence: "+self.LastOccurrence
        if self.Value:
            sum += "  Value: "+self.Value
        if self.Expectation:
            sum += "  Expectation: "+self.Expectation
        if self.C:
            sum += "  C: "+self.C
        if self.SAPNote:
            sum += "  SAPNote: "+self.SAPNote
        if self.TraceText:
            sum += "  TraceText: "+self.TraceText
        return sum
    def printMiniCheck(self):  
        print(self.summary())
        
class ParameterCheck:
    def __init__(self, IniFile, Section, Parameter, Priority, ConfiguredValue, RecommendedValue, SAPNote, ConfiguredLayer, Revision, Environment, CpuThreads, CpuFrequency, NumaNodes, GlobalAllocationLimit, SlaveNodes, LogVolumeSize):
        self.IniFile = IniFile
        self.Section = Section
        self.Parameter = Parameter
        self.Priority = Priority
        self.ConfiguredValue = ConfiguredValue
        self.RecommendedValue = RecommendedValue
        self.SAPNote = SAPNote
        self.ConfiguredLayer = ConfiguredLayer
        self.Revision = Revision
        self.Environment = Environment
        self.CpuThreads = CpuThreads
        self.CpuFrequency = CpuFrequency
        self.NumaNodes = NumaNodes
        self.GlobalAllocationLimit = GlobalAllocationLimit
        self.SlaveNodes = SlaveNodes
        self.LogVolumeSize = LogVolumeSize
    def summary(self):
        sum = "\nParameter '"+self.Parameter+"' in configuration file '"+self.IniFile+"' and in section '"+self.Section+"'"
        if "-- not set --" in self.ConfiguredValue:
            sum += ", is not configured"
        else:
            sum += ", is configured to '"+self.ConfiguredValue+"' in "+self.ConfiguredLayer+" layer"
        if "-- check why set --" in self.RecommendedValue:
            sum += ", but has no recommended value, so please check why it is set."
        else:
            sum += ", but the recommendation is '"+self.RecommendedValue+"'."
        if self.SAPNote:
            sum += " For more information see SAP Note "+self.SAPNote+"."
        if self.Priority:
            sum += " This has priority "+self.Priority+"."
        sum += "\nFollowing scenario has been taken into account:\n"
        if self.Revision:
            sum += "Revision: "+self.Revision
        if self.Environment:
            sum += "  Environment: "+self.Environment
        if self.CpuThreads:
            sum += "  CpuThreads: "+self.CpuThreads
        if self.CpuFrequency:
            sum += "  CpuFrequency: "+self.CpuFrequency
        if self.NumaNodes:
            sum += "  NumaNodes: "+self.NumaNodes
        if self.GlobalAllocationLimit:
            sum += "  GlobalAllocationLimit: "+self.GlobalAllocationLimit
        if self.SlaveNodes:
            sum += "  SlaveNodes: "+self.SlaveNodes
        if self.LogVolumeSize:
            sum += "  LogVolumeSize: "+self.LogVolumeSize
        return sum     
        
class SQLWithRecommendation:
    def __init__(self, Hash, Type, Origin, Engine):
        self.Hash = Hash
        sql_types = {"AI":"ALTER INDEX", "AS":"ALTER SYSTEM", "AT":"ALTER TABLE", "AL":"ALTER", "CA":"CALL", "CI":"CREATE INDEX", "CO":"COMMIT", "CR":"CREATE", "DE":"DELETE", "DI":"DROP INDEX", "DM":"Data Modification", "DT":"DROP TABLE", "DR":"DROP", "EX":"EXECUTE", "IN":"INSERT", "RE":"REPLACE", "RO":"ROLLBACK", "SU":"SELECT FOR UPDATE", "SE":"SELECT", "ST":"START TASK", "TR":"TRUNCATE", "UP":"UPDATE", "US":"UPSERT", "WI":"WITH"}
        if Type in sql_types:
            self.Type = sql_types[Type]
        else:
            self.Type = " Unknown Type "
        self.Type = Type
        sql_origins = {"AB": "ABAP", "BA": "Backup Scheduler", "CO": "SAP HANA Cockpit", "CR": "Crystal reports", "DS": "Data Services", "EW": "Extended warehouse management", "FC": "Business Objects", "HA": "SAP Host Agenet", "HQ": "hdbsql", "HS": "SAP HANA Studio", "IA": "Information Access", "IF": "Informatica", "IN": "Internal Request", "IS": "indexserver", "LU": "Lumira", "MS": "MicroStrategy",  "PA": "Patrol", "PY": "Python", "RT": "R3trans", "SC": "sapdbctrl", "SD": "SDA", "ST": "Statistics server", "TA": "Tableau", "UN": "unknown", "VO": "SAP HANA Vora", "WI": "Web Intelligence", "XC": "XS Classic", "XS": "XSA",  "XI": "XimoStudio", "XM": "XML/A"}
        if Origin in sql_origins:
            self.Origin = sql_origins[Origin]
        else:
            self.Origin = " No SQL Origin Specified "
        engines = {"C":"Column", "E":"ESX", "H":"HEX", "O":"OLAP", "R":"Row"}
        if Engine in engines:
            self.Engine = engines[Engine]
        else:
            self.Engine = " Unknown Engine "
    def summary(self):
        sum = "\nSQL statement "+self.Hash+" is one of the most expensive statements in the SQL cache and there is a recommendation available in SAP Note 2000002.\n"
        sum += "This SQL statement is of type "+self.Type+", originates from "+self.Origin
        if self.Engine:
            sum += ", and executed by the "+self.Engine+" engine."
        else:
            sum += "."
        return sum

class LogManager:
    def __init__(self, std_out, out_dir, SID, emailSender = "", db = ""):
        self.std_out = std_out
        self.out_dir = out_dir
        self.SID = SID
        self.emailSender = emailSender
        self.db = db

class SQLManager:
    def __init__(self, hdbsql_string, dbuserkey, dbase):
        self.key = dbuserkey
        self.db = dbase
        if len(dbase) > 1:
            self.hdbsql_jAU = hdbsql_string + " -j -A -U " + self.key + " -d " + self.db
            self.hdbsql_jAaxU = hdbsql_string + " -j -A -a -x -U " + self.key + " -d " + self.db
        else:            
            self.hdbsql_jAU = hdbsql_string + " -j -A -U " + self.key
            self.hdbsql_jAaxU = hdbsql_string + " -j -A -a -x -U " + self.key



######################## DEFINE FUNCTIONS ################################

def run_command(cmd, ignore_error = False):  #ignore_error only makes sense in Python 2
    if sys.version_info[0] == 2: 
        if ignore_error:
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).strip("\n")
        else:
            out = subprocess.check_output(cmd, shell=True).strip("\n")
    elif sys.version_info[0] == 3:  #run().stderr is ignored
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip("\n")
    else:
        print("ERROR: Wrong Python version")
        os._exit(1)
    return out

def is_integer(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False
    
def is_email(s):
    s = s.split('@')
    if not len(s) == 2:
        return False
    return '.' in s[1]

def cdalias(alias):   # alias e.g. cdtrace, cdhdb, ...
    #command_run = subprocess.check_output(['/bin/bash', '-i', '-c', "alias "+alias])
    process = subprocess.Popen(['/bin/bash', '-i', '-c', "alias "+alias], stdout=subprocess.PIPE)
    out, err = process.communicate()
    out = out.decode()
    pieces = out.strip("\n").strip("alias "+alias+"=").strip("'").strip("cd ").split("/")
    path = ''
    for piece in pieces:
        if piece[0] == '$':
            #piece = (subprocess.check_output(['/bin/bash', '-i', '-c', "echo "+piece])).strip("\n")
            process = subprocess.Popen(['/bin/bash', '-i', '-c', "echo "+piece], stdout=subprocess.PIPE)
            out, err = process.communicate()
            out = out.decode().strip("\n")
        path = path + '/' + piece + '/' 
    return path       
        
def checkUserKey(dbuserkey, virtual_local_host, logman, error_emails):
    try: 
        #key_environment = subprocess.check_output('''hdbuserstore LIST '''+dbuserkey, shell=True) 
        key_environment = run_command('''hdbuserstore LIST '''+dbuserkey)
        if "NOT FOUND" in key_environment:
            message = "ERROR, the key "+dbuserkey+" is not maintained in hdbuserstore."
            log_with_emails(message, logman, error_emails)
            os._exit(1)
    except:
        message = "ERROR, the key "+dbuserkey+" is not maintained in hdbuserstore."
        log_with_emails(message, logman, error_emails)
        os._exit(1)
    #local_host = subprocess.check_output("hostname", shell=True).replace('\n','') if virtual_local_host == "" else virtual_local_host
    local_host = run_command("hostname").replace('\n','') if virtual_local_host == "" else virtual_local_host
    if not is_integer(local_host.split('.')[0]):    #first check that it is not an IP address
        local_host = local_host.split('.')[0]  #if full host name is specified in the local host (or virtual host), only the first part is used
    ENV = key_environment.split('\n')[1].replace('  ENV : ','').split(',')
    #key_hosts = [env.split(':')[0] for env in ENV]
    key_hosts = [env.split(':')[0].split('.')[0] for env in ENV]  #if full host name is specified in the Key, only the first part is used
    if not local_host in key_hosts:
        message = "ERROR, local host, "+local_host+", should be one of the hosts specified for the key, "+dbuserkey+" (in case of virtual, please use -vlh, see --help for more info)"
        log_with_emails(message, logman, error_emails)
        os._exit(1)    
    
def checkAndConvertBooleanFlag(boolean, flagstring):     
    boolean = boolean.lower()
    if boolean not in ("false", "true"):
        print("INPUT ERROR: ", flagstring, " must be either 'true' or 'false'. Please see --help for more information.")
        os._exit(1)
    boolean = True if boolean == "true" else False
    return boolean
        
def convertToCheckId(checkType, checkNumber):
    return checkType+'0'*(4-len(str(checkNumber)))+str(checkNumber)        
        
def is_check_id(checkString):
    if not len(checkString) == 5:
        return False
    if checkString[0] not in ['M', 'I', 'S', 'T', 'C', 'A']:
        return False
    if not is_integer(checkString[1:5].lstrip('0')):
        return False
    return True
    
def get_check_type(checkString):
    if not is_check_id(checkString):
        print("ERROR: checkString, "+checkString+", in get_check_type is not a check ID")
        os._exit(1)
    return checkString[0]
    
def get_check_number(checkString):
    if not is_check_id(checkString):
        print("ERROR: checkString in get_check_numer is not a check ID")
        os._exit(1)
    return int(checkString[1:5].lstrip('0'))
        
def checkIfAcceptedFlag(word):
    if not is_check_id(word.strip('-')):
        if not word in ["-h", "--help", "-d", "--disclaimer", "-cg", "-pe", "-se", "-ee", "-is", "-at", "-abs", "-ip", "-oe", "-as", "-ca", "-ic", "-il", "-vlh", "-mf", "-zf", "-ct", "-ff", "-od", "-so", "-oc", "-enc", "-ens", "-enm", "-en", "-hci", "-ssl", "-k", "-dbs"]:
            print("INPUT ERROR: ", word, " is not one of the accepted input flags. Please see --help for more information.")
            os._exit(1)

def getParameterFromFile(flag, flag_string, flag_value, flag_file, flag_log, parameter):
    if flag == flag_string:
        parameter = flag_value
        flag_log[flag_string] = [flag_value, flag_file]
    return parameter

def getParameterListFromFile(flag, flag_string, flag_value, flag_file, flag_log, parameter, delimeter = ','):
    if flag == flag_string:
        parameter = [x for x in flag_value.split(delimeter)]
        flag_log[flag_string] = [flag_value, flag_file]
    return parameter

def getParameterFromCommandLine(sysargv, flag_string, flag_log, parameter):
    if flag_string in sysargv:
        flag_value = sysargv[sysargv.index(flag_string) + 1]
        parameter = flag_value
        flag_log[flag_string] = [flag_value, "command line"]
    return parameter

def getParameterListFromCommandLine(sysargv, flag_string, flag_log, parameter, delimeter = ','):
    if flag_string in sysargv:
        parameter = [x for x in sysargv[  sysargv.index(flag_string) + 1   ].split(delimeter)]
        flag_log[flag_string] = [','.join(parameter), "command line"]
    return parameter

def log(message, logman, file_name = "", recieversEmail = ""):
    logMessage = message if htmlSend else '"'+message+'"'
    if logman.emailSender:    
        logMessage += " is sent to " + recieversEmail if recieversEmail else message
    if logman.std_out:
        print(logMessage)
    if file_name == "":
        file_name = "hanacheckerlog"
    logfile = open(logman.out_dir+"/"+file_name+"_"+datetime.now().strftime("%Y-%m-%d_%H-%M-%S"+".txt").replace(" ", "_"), "a")
    logfile.write(logMessage+"\n")   
    logfile.flush()
    logfile.close()
    if recieversEmail:
        if logman.emailSender:   #if -enc was specified as empty, then emailSender is None, so no emails will be send
            mailstring = 'echo "'+message.replace('"','')+'" | '+logman.emailSender.emailClient+' -s "HANAChecker: Potential Critical Situation(s) '+logman.db+"@"+logman.SID+'!" '
            if logman.emailSender.mailServer:
                mailstring += ' -S smtp=smtp://'+logman.emailSender.mailServer+' '
            if logman.emailSender.senderEmail:
                mailstring += ' -S from="'+logman.emailSender.senderEmail+'" '
            mailstring += recieversEmail
            #subprocess.check_output(mailstring, shell=True)
            dummyout = run_command(mailstring)

def log_with_emails(message, logman, error_emails):
    if error_emails:
        for error_email in error_emails:
            log(message, logman, recieversEmail = error_email)
    else:
        log(message, logman)

def hana_version_rev_mrev(sqlman):
    #command_run = subprocess.check_output(sqlman.hdbsql_jAU + " \"select value from sys.m_system_overview where name = 'Version'\"", shell=True)
    command_run = run_command(sqlman.hdbsql_jAU + " \"select value from sys.m_system_overview where name = 'Version'\"")
    hanaver = command_run.splitlines(1)[2].split('.')[0].replace('| ','')
    hanarev = command_run.splitlines(1)[2].split('.')[2]
    hanamrev = command_run.splitlines(1)[2].split('.')[3]
    if not is_integer(hanarev):
        print("ERROR: something went wrong checking hana revision.")
        os._exit(1)
    return [int(hanaver), int(hanarev), int(hanamrev)]

def get_file_revision_number_str(file_name, base_file_name, tmp_sql_dir):
    if '+' not in file_name:
        file_revision = '0'
    else:
        file_revision = file_name.split(tmp_sql_dir+base_file_name+'_')[1].split('+')[0] 
        if not file_revision:
            file_revision = '0'
        file_revision = file_revision.split('.')
        if len(file_revision) == 3:
            file_revision = file_revision[0]+file_revision[1]+file_revision[2]+'00'  #then maintanance revision is 00 
        elif len(file_revision) == 4:
            file_revision = file_revision[0]+file_revision[1]+file_revision[2]+file_revision[3]
        else:
            print("ERROR: Something went wrong with file revision.")
            os._exit(1)
    return file_revision 

def get_revision_number_str(version, revision, mrevision):
    mrevision_str = str(mrevision)
    if mrevision < 10:
        mrevision_str = '0'+str(mrevision)
    revision_str = '00'+str(revision)
    if revision < 10:
        revision_str = '0000'+str(revision)
    elif revision < 100:
        revision_str = '000'+str(revision)
    return str(version)+revision_str+mrevision_str                   
        
def getFileVersion(base_file_name, tmp_sql_dir, version, revision, mrevision):
    revision_number_str = get_revision_number_str(version, revision, mrevision)
    try:
        #output = subprocess.check_output('ls '+tmp_sql_dir+base_file_name+'_[12]* '+tmp_sql_dir+base_file_name+'.txt', shell=True, stderr=subprocess.STDOUT) #removes SHC
        output = run_command('ls '+tmp_sql_dir+base_file_name+'_[12]* '+tmp_sql_dir+base_file_name+'.txt', True)   #[12] removes SHC
    except Exception as e:
        output = str(e.output)
    output = output.splitlines(1)
    files = [f.strip('\n') for f in output if not 'cannot access' in f]
    if len(files) == 0:
        print("ERROR: There were no on-premise files found with name "+base_file_name+", files = ", files)
        os._exit(1)
    chosen_file_name = files[0] 
    for file_name in files:
        file_revision_number_str = get_file_revision_number_str(file_name, base_file_name, tmp_sql_dir)
        choosen_file_revision_number_str = get_file_revision_number_str(chosen_file_name, base_file_name, tmp_sql_dir)
        if int(file_revision_number_str) <= int(revision_number_str) and int(file_revision_number_str) > int(choosen_file_revision_number_str):
            chosen_file_name = file_name
    return chosen_file_name

def getCheckFiles(tmp_sql_dir, check_types, version, revision, mrevision, active_threads, abap_schema):
    check_files = []
    for ct in check_types:
        if ct == 'M':
            check_files.append(getFileVersion('HANA_Configuration_MiniChecks', tmp_sql_dir, version, revision, mrevision))    
        elif ct == 'I':
            check_files.append(getFileVersion('HANA_Configuration_MiniChecks_Internal', tmp_sql_dir, version, revision, mrevision))
        elif ct == 'S':
            check_files.append(getFileVersion('HANA_Security_MiniChecks', tmp_sql_dir, version, revision, mrevision))
        elif ct == 'T':
            check_files.append(getFileVersion('HANA_TraceFiles_MiniChecks', tmp_sql_dir, version, revision, mrevision))
        elif ct == 'P':
            check_files.append(getFileVersion('HANA_Configuration_Parameters', tmp_sql_dir, version, revision, mrevision))
        elif ct == 'C':
            revision_number_str = get_revision_number_str(version, revision)
            if int(revision_number_str) < 200040:
                print("COMPATIBILITY ERRROR: There are no Call Stack Mini-Checks for your SAP HANA revision, so you cannot use -ct C")
                os._exit(1)
            if active_threads:  # then must change modification section
                cs_mc_file = getFileVersion('HANA_Threads_Callstacks_MiniChecks', tmp_sql_dir, version, revision).strip('\n')
                cs_mc_file_temp = tmp_sql_dir+"HANA_Threads_Callstacks_MiniChecks_Temp.txt"
                fin = open(cs_mc_file, "rt")
                fout = open(cs_mc_file_temp, "wt") # will be removed when tmp_sql_dir is removed 
                for line in fin:
                    fout.write(line.replace('0.2 MIN_ACTIVE_THREADS', active_threads+' MIN_ACTIVE_THREADS'))
                fin.close()
                fout.close()
                check_files.append(cs_mc_file_temp)
            else:
                check_files.append(getFileVersion('HANA_Threads_Callstacks_MiniChecks', tmp_sql_dir, version, revision))
        elif ct == 'R':
            check_files.append(getFileVersion('HANA_SQL_SQLCache_TopLists', tmp_sql_dir, version, revision))
        elif ct == 'A':
            abap_mc_file = getFileVersion('HANA_ABAP_MiniChecks', tmp_sql_dir, version, revision).strip('\n')
            abap_mc_file_temp = tmp_sql_dir+"HANA_ABAP_MiniChecks_Temp.txt"
            fin = open(abap_mc_file, "rt")
            fout = open(abap_mc_file_temp, "wt") # will be removed when tmp_sql_dir is removed
            fout.write("SET SCHEMA "+abap_schema+"; ") 
            for line in fin:
                fout.write(line)
            fin.close()
            fout.close()
            check_files.append(abap_mc_file_temp)
    return check_files        
        
def getCriticalChecks(check_files, ignore_check_why_set, ignore_dublicated_parameter, ignore_checks, sqlman, logman): 
    revision = ''
    environment = ''
    cputhreads = ''
    cpufrequency = ''
    numa_nodes = ''
    global_allocation_limit = ''
    slave_nodes = ''
    log_volume_size = ''
    critical_mini_checks = []
    critical_parameter_checks = []
    sqls_with_recommendation = []
    for check_file in check_files:
        checkType = 'M'
        if 'Internal' in check_file:
            checkType = 'I'
        elif 'Security' in check_file:
            checkType = 'S'
        elif 'Trace' in check_file:
            checkType = 'T'
        elif 'Parameters' in check_file:
            checkType = 'P'
        elif 'Callstacks' in check_file:
            checkType = 'C'
        elif 'SQLCache_TopLists' in check_file:
            checkType = 'R'
        elif 'ABAP' in check_file:
            checkType = 'A'
        try:
            #result = subprocess.check_output(sqlman.hdbsql_jAaxU + ' -I '+check_file, shell=True).splitlines()
            result = run_command(sqlman.hdbsql_jAaxU + ' -I '+check_file).splitlines()
        except:
            log("ERROR: The check file "+check_file+" could not be executed. Either there is a problem with the check file (did you get the latest SQLStatements.zip from SAP Note 1969700?) or there is a problem with the user (is user properly saved in hdbuserstore?) or there is another problem (OOM?).", logman)
            os._exit(1)
        result = [ [word.strip(' ') for word in line.split('|')] for line in result]           
        old_checkId = "-1"
        old_description = ""
        for line in result:
            if len(line) > 1:
                if checkType == 'P':
                    if "Revision:" in line[1]:
                        revision = line[2]
                    elif "Environment:" in line[1]:
                        environment = line[2]
                    elif "CPU threads:" in line[1]:
                        cputhreads = line[2]
                    elif "CPU frequency (MHz):" in line[1]:
                        cpufrequency = line[2]
                    elif "NUMA nodes:" in line[1]:
                        numa_nodes = line[2]
                    elif "GAL (GB):" in line[1]:
                        global_allocation_limit = line[2]
                    elif "Slave_nodes" in line[1]:
                        slave_nodes = line[2]
                    elif "Log volume size (GB):" in line[1]:
                        log_volume_size = line[2]
                    elif line[9] and line[10]:    # if implementation and undo command exist then
                        if cputhreads == '0' or cpufrequency == '0' or numa_nodes == '?' or global_allocation_limit == '?' or log_volume_size == '?':
                            log("PRIVILEGE ERROR: The user represented by the key in the hdbuserstore has insufficient privileges.", logman)
                            log("Make sure he has sufficient privileges to read these:", logman)
                            log("CPU threads: "+cputhreads+"   CPU frequency: "+cpufrequency+"   NUMA nodes: "+numa_nodes+"   GAL (GB): "+global_allocation_limit+"   Log volume size (GB): "+log_volume_size, logman)
                            log("Suggestion: The role MONITORING could help.", logman)
                            os._exit(1)                           
                        inifile = line[1]
                        section = line[2]
                        parameter = line[3]
                        priority = line[4]
                        if "90+" in check_file:   #has a default value on position [5] that we will not take
                            configuredvalue= line[6]
                            recommendedvalue = line[7]
                            sapnote = line[8]
                            configuredlayer = line[9]
                        else:
                            configuredvalue= line[5]
                            recommendedvalue = line[6]
                            sapnote = line[7]
                            configuredlayer = line[8]
                        if not ignore_dublicated_parameter or not parameter_is_dublicate(inifile, section, parameter, configuredvalue, critical_parameter_checks):
                            if not ignore_check_why_set or not "-- check why set --" in recommendedvalue:                                                        
                                if parameter in ['allocationlimit', 'statement_memory_limit', 'max_partitions_limited_by_locations']: 
                                    critical_parameter_checks.append(ParameterCheck(inifile, section, parameter, priority, configuredvalue, recommendedvalue, sapnote, configuredlayer, revision, environment, '', '', '', global_allocation_limit, '', ''))    
                                elif parameter in ['default_statement_concurrency_limit', 'max_concurrency', 'max_concurrency_hint', 'num_cores', 'max_gc_parallelity', 'tables_preloaded_in_parallel']:
                                    critical_parameter_checks.append(ParameterCheck(inifile, section, parameter, priority, configuredvalue, recommendedvalue, sapnote, configuredlayer, revision, environment, cputhreads, '', '', '', '', ''))    
                                elif parameter in ['savepoint_pre_critical_flush_retry_threshold']:
                                    critical_parameter_checks.append(ParameterCheck(inifile, section, parameter, priority, configuredvalue, recommendedvalue, sapnote, configuredlayer, revision, environment, '', cpufrequency, '', '', '', ''))           
                                elif parameter in ['logshipping_max_retention_size']:
                                    critical_parameter_checks.append(ParameterCheck(inifile, section, parameter, priority, configuredvalue, recommendedvalue, sapnote, configuredlayer, revision, environment, '', '', '', '', '', log_volume_size))
                                elif parameter in ['max_partitions']: 
                                    critical_parameter_checks.append(ParameterCheck(inifile, section, parameter, priority, configuredvalue, recommendedvalue, sapnote, configuredlayer, revision, environment, '', '', '', global_allocation_limit, slave_nodes, ''))    
                                else:    
                                    critical_parameter_checks.append(ParameterCheck(inifile, section, parameter, priority, configuredvalue, recommendedvalue, sapnote, configuredlayer, revision, environment, '', '', '', '', '', ''))
                elif checkType == 'R':
                    if ("1.00.122" in check_file and line[4] == 'X') or ("1.00.122" not in check_file and line[5] == 'X'):
                        sql_hash = line[1]
                        if not hash_is_dublicate(sql_hash, sqls_with_recommendation):
                            sql_type = line[2]
                            origin = line[3]
                            engine = ''
                            if revision >= 53:
                                engine = line[4] 
                            sqls_with_recommendation.append(SQLWithRecommendation(sql_hash, sql_type, origin, engine))
                elif is_check_id(line[1]):  # then this line is an M, I, S, T, C, or A mini-check
                    if not line[1] in ignore_checks:
                        if checkType == 'T':
                            potential_critical = 'X'
                            checkId = line[1]
                            area = line[2]
                            description = line[3]
                            host = line[4]
                            port = line[5]
                            count = line[6]
                            last_occurrence = line[7]
                            sap_note = line[8]
                            trace_text = line[9]
                            critical_mini_checks.append(MiniCheck(checkId, area, description, host, port, count, '', last_occurrence, '', '', potential_critical, sap_note, trace_text))
                        if checkType == 'C':
                            potential_critical = 'X'
                            checkId = line[1]
                            area = line[2]
                            description = line[3]
                            host = line[4]
                            port = line[5]
                            count = line[6]
                            act_thr = line[7]
                            last_occurrence = line[8]
                            sap_note = line[9]
                            details = line[10]
                            critical_mini_checks.append(MiniCheck(checkId, area, description, host, port, count, act_thr, last_occurrence, '', '', potential_critical, sap_note, details))
                        else: # M, I, S, A 
                            potential_critical = line[6] if checkType in ['M','I'] else line[5] #'M', 'I' column 6, but for 'S' and 'A' column 5
                            if potential_critical == 'X':
                                checkId = line[1] if line[1] else old_checkId
                                description = line[2] if line[2] else old_description
                                host = line[3] if checkType in ['M','I'] else ''    #no host for 'S' or 'A'
                                value = line[4] if checkType in ['M','I'] else line[3]
                                expected_value = line[5] if checkType in ['M','I'] else line[4]
                                sap_note = line[7] if checkType in ['M','I'] else line[6]
                                #//@audit-info instantiate MiniCheck
                                critical_mini_checks.append(MiniCheck(checkId, '', description, host, '', '', '', '', value, expected_value, potential_critical, sap_note, ''))
                            old_checkId = line[1] if line[1] else old_checkId
                            old_description = line[2] if line[2] else old_description    
    return [critical_mini_checks, critical_parameter_checks, sqls_with_recommendation]
    
def ping_db(sqlman, logman, error_emails):
    with open(os.devnull, 'w') as devnull:  # just to get no stdout in case HANA is offline
        try:
            #command_run = subprocess.check_output(sqlman.hdbsql_jAaxU + ' "select * from dummy"', shell=True, stderr=devnull).splitlines(1)
            command_run = run_command(sqlman.hdbsql_jAaxU + ' "select * from dummy"').splitlines(1) #this might be a problem ... from https://docs.python.org/3/library/subprocess.html#subprocess.getoutput : 
            #The stdout and stderr arguments may not be supplied at the same time as capture_output. If you wish to capture and combine both streams into one, use stdout=PIPE and stderr=STDOUT instead of capture_output.
            output = command_run[0].strip("\n").strip("|").strip(" ")
            if not output == 'X':
                message = "CONNECTION ERROR: Something went wrong getting results from an SQL from database "+sqlman.db+" with user "+sqlman.key+".\n"
                log_with_emails(message, logman, error_emails)
                os._exit(1)
        except:
            message = "CONNECTION ERROR: Something went wrong connecting to the database "+sqlman.db+" with user "+sqlman.key+".\n"
            log_with_emails(message, logman, error_emails)
            os._exit(1)

def parameter_is_dublicate(inifile, section, parameter, configuredvalue, critical_parameter_checks): #find parameters set to same value in different layers
    for check in critical_parameter_checks:
        if inifile == check.IniFile and section == check.Section and parameter == check.Parameter and configuredvalue == check.ConfiguredValue:
            return True
    return False

def hash_is_dublicate(hash, sqls_with_recommendation): 
    for sql in sqls_with_recommendation:
        if hash == sql.Hash:
            return True
    return False
    
def addCheckGroupsToDict(checkEmailDict, check_groups):
    global chidMax
    for checkNumber in range(1, chidMax):    
        for cg in check_groups:
            if get_check_number(cg[0][0]) <= checkNumber <= get_check_number(cg[0][1]):
                checkType = get_check_type(cg[0][0])
                if checkNumber in list(checkEmailDict[checkType].keys()):
                    if cg[1] not in checkEmailDict[checkType][checkNumber]:
                        checkEmailDict[checkType][checkNumber].append(cg[1])
                else:
                    checkEmailDict[checkType][checkNumber] = [cg[1]]     
    return checkEmailDict
    
def addCatchAllEmailsToDict(checkEmailDict, catch_all_emails, ignore_checks_for_ca):
    global chidMax
    for checkType in ['M', 'I', 'S', 'T', 'C', 'A']: #mini, internal, security, trace, call stacks, ABAP
        for checkNumber in range(1, chidMax):
            if convertToCheckId(checkType, checkNumber) not in ignore_checks_for_ca:
                if checkNumber in list(checkEmailDict[checkType].keys()):
                    for ca_email in catch_all_emails:
                        if ca_email not in checkEmailDict[checkType][checkNumber]:
                            checkEmailDict[checkType][checkNumber].append(ca_email)
                else:
                    checkEmailDict[checkType][checkNumber] = catch_all_emails  
    return checkEmailDict
    
def sendEmails(critical_checks, checkEmailDict, parameter_emails, sql_emails, one_email, always_send, check_files, execution_string, out_config, flag_log, logman):
    critical_mini_checks = critical_checks[0]
    critical_parameter_checks = critical_checks[1]
    sqls_with_recommendation = critical_checks[2]
    messages = {}
    dbstring = ""
    parameter_string = " "
    if out_config:
        parameter_string = " with"
        for key, value in flag_log.items():
            parameter_string += "\n"+key
            for i in range(0, len(value), 2):
                parameter_string += "\t"+value[i]+" from "+value[i+1]
    if len(logman.db) > 1:
        dbstring = logman.db+'@' 
    if always_send:
        unique_emails = []
        for val in checkEmailDict.values():
            for emails in val.values():
                for email in emails:
                    if email not in unique_emails:
                        unique_emails.append(email)
        always_send_message = "HANAChecker was executed "+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+parameter_string+" on "+dbstring+logman.SID+" with \n"+execution_string+"\nIf any of the mini and/or parameter checks from following check files:"
        always_send_message += ",".join(check_files)
        always_send_message += "\nthat you are responsible for seem critical, you will be notified now.\n"
        for email in unique_emails:
            messages.update({email:[always_send_message]})
        for email in parameter_emails:
            if email not in unique_emails:
                messages.update({email:[always_send_message]})
        for email in sql_emails:
            if email not in unique_emails:
                messages.update({email:[always_send_message]})
    for i, check in enumerate(critical_mini_checks): #//@audit-info compose messages
        if check.Number in list(checkEmailDict[check.Type].keys()):
            for email in checkEmailDict[check.Type][check.Number]:
                if email in messages:
                    if htmlSend and i == len(critical_mini_checks) - 1:
                        messages[email].append("</table>")
                    else:
                        messages[email].append(check.summary())
                else: # once per email message
                    if htmlSend:
                        messages.update({email:["<table><tr>"+"".join(["<th>"+e+"</th>" for e in vars(check).keys()])+"</tr>"]})
                        messages[email].append(check.summary())
                    else:
                        messages.update({email:[check.summary()]})
    for check in critical_parameter_checks:
        for email in parameter_emails:
            if email in messages:
                messages[email].append(check.summary())
            else:
                messages.update({email:[check.summary()]})
    for sql in sqls_with_recommendation:
        for email in sql_emails:
            if email in messages:
                messages[email].append(sql.summary())
            else:
                messages.update({email:[sql.summary()]})
    for email, messages_for_email in messages.items(): #//@audit-info send messages
        if one_email:
            message = "\n".join(messages_for_email)
            log(message, logman, recieversEmail = email)
        else:
            for message in messages_for_email:
                log(message, logman, recieversEmail = email)
                
    
def main():
    ### globals ###
    global chidMax
    
    #####################  CHECK PYTHON VERSION ###########
    if sys.version_info[0] != 2 and sys.version_info[0] != 3:
        if sys.version_info[1] != 7:
            print("VERSION ERROR: hanachecker is only supported for Python 2.7.x (for HANA 2 SPS05 and lower) and for Python 3.7.x (for HANA 2 SPS06 and higher). Did you maybe forget to log in as <sid>adm before executing this?")
            os._exit(1)
    if sys.version_info[0] == 3:
        print("VERSION WARNING: You are among the first using HANAChecker on Python 3. As always, use on your own risk, and please report issues to christian.hansen01@sap.com. Thank you!")

    #####################   DEFAULTS   ####################
    email_client = 'mailx'   #default email client
    email_sender_address = ''
    mail_server = ''
    email_sender = []    #depricated!
    hanachecker_interval = -1
    ignore_check_why_set = "false"
    active_threads = ''
    abap_schema = ''
    ignore_dublicated_parameter = "true"
    one_email = "false"
    always_send = "false"
    ssl = "false"
    virtual_local_host = "" #default: assume physical local host
    dbuserkeys = ["SYSTEMKEY"] # This/these KEY(S) has to be maintained in hdbuserstore  
                               # so that   hdbuserstore LIST    gives e.g. 
                               # KEY SYSTEMKEY
                               #     ENV : mo-fc8d991e0:30015
                               #     USER: SYSTEM
    dbases = ['']
    std_out = "1" #print to std out
    out_config = "false"
    out_dir = "/tmp/hanachecker_output"
    flag_files = []     #default: no configuration input file
    check_files = None
    zip_file = None
    check_types = []
    checkEmailDict = {'M':{}, 'I':{}, 'S':{}, 'T':{}, 'C':{}, 'A':{}}  #mini, internal, security, trace, call stack, ABAP
    check_groups = []
    parameter_emails = []
    sql_emails = []
    error_emails = []
    catch_all_emails = []
    ignore_checks_for_ca = []
    ignore_checks = []

    
    #####################  CHECK INPUT ARGUMENTS #################
    if len(sys.argv) == 1:
        print("INPUT ERROR: hanachecker needs input arguments. Please see --help for more information.")
        os._exit(1) 
    if len(sys.argv) != 2 and len(sys.argv) % 2 == 0:
        print("INPUT ERROR: Wrong number of input arguments. Please see --help for more information.")
        os._exit(1)
    for i in range(len(sys.argv)):
        if i % 2 != 0:
            if sys.argv[i][0] != '-':
                print("INPUT ERROR: Every second argument has to be a flag, i.e. start with -. Please see --help for more information.")
                os._exit(1)    
    
    #####################   PRIMARY INPUT ARGUMENTS   ####################
    flag_log = {}
    for word in sys.argv:
        if word[0:1] == '-':
            checkIfAcceptedFlag(word)     
    if '-h' in sys.argv or '--help' in sys.argv:
        printHelp() 
    if '-d' in sys.argv or '--disclaimer' in sys.argv:
        printDisclaimer() 
    flag_files = getParameterListFromCommandLine(sys.argv, '-ff', flag_log, flag_files)
     
    ############ CONFIGURATION FILE ###################
    for flag_file in flag_files:
        with open(flag_file, 'r') as fin:
            check_groups = [] # only one config file can define -cg
            flag_log.pop('-cg', None)
            for line in fin:
                firstWord = line.strip(' ').split(' ')[0]  
                if firstWord[0:1] == '-':
                    checkIfAcceptedFlag(firstWord)
                    flagValue = line.strip(' ').split('"')[1].strip('\n').strip('\r') if line.strip(' ').split(' ')[1][0] == '"' else line.strip(' ').split(' ')[1].strip('\n').strip('\r')
                    email_client                        = getParameterFromFile(firstWord, '-enc', flagValue, flag_file, flag_log, email_client)
                    email_sender_address                = getParameterFromFile(firstWord, '-ens', flagValue, flag_file, flag_log, email_sender_address)
                    mail_server                         = getParameterFromFile(firstWord, '-enm', flagValue, flag_file, flag_log, mail_server)
                    email_sender                        = getParameterListFromFile(firstWord, '-en', flagValue, flag_file, flag_log, email_sender)  #depricated
                    hanachecker_interval                = getParameterFromFile(firstWord, '-hci', flagValue, flag_file, flag_log, hanachecker_interval)
                    ignore_check_why_set                = getParameterFromFile(firstWord, '-is', flagValue, flag_file, flag_log, ignore_check_why_set)
                    active_threads                      = getParameterFromFile(firstWord, '-at', flagValue, flag_file, flag_log, active_threads)
                    abap_schema                         = getParameterFromFile(firstWord, '-abs', flagValue, flag_file, flag_log, abap_schema)
                    ignore_dublicated_parameter         = getParameterFromFile(firstWord, '-ip', flagValue, flag_file, flag_log, ignore_dublicated_parameter)
                    one_email                           = getParameterFromFile(firstWord, '-oe', flagValue, flag_file, flag_log, one_email)
                    always_send                         = getParameterFromFile(firstWord, '-as', flagValue, flag_file, flag_log, always_send)
                    ssl                                 = getParameterFromFile(firstWord, '-ssl', flagValue, flag_file, flag_log, ssl)
                    virtual_local_host                  = getParameterFromFile(firstWord, '-vlh', flagValue, flag_file, flag_log, virtual_local_host)
                    dbuserkeys                          = getParameterListFromFile(firstWord, '-k', flagValue, flag_file, flag_log, dbuserkeys)
                    std_out                             = getParameterFromFile(firstWord, '-so', flagValue, flag_file, flag_log, std_out)
                    out_config                          = getParameterFromFile(firstWord, '-oc', flagValue, flag_file, flag_log, out_config)
                    out_dir                             = getParameterFromFile(firstWord, '-od', flagValue, flag_file, flag_log, out_dir)
                    check_files                         = getParameterListFromFile(firstWord, '-mf', flagValue, flag_file, flag_log, check_files)
                    zip_file                            = getParameterFromFile(firstWord, '-zf', flagValue, flag_file, flag_log, zip_file)
                    check_types                         = getParameterListFromFile(firstWord, '-ct', flagValue, flag_file, flag_log, check_types)
                    for checkFlagType in ['M', 'I', 'S', 'T', 'C', 'A']: #mini, internal, security, trace, call stack, ABAP
                        for checkFlagNumber in range(1, chidMax):
                            checkId = convertToCheckId(checkFlagType, checkFlagNumber)
                            if firstWord == '-'+checkId:
                                checkEmailDict[checkFlagType][checkFlagNumber] = [x for x in flagValue.split(',')]
                                flag_log['-'+checkId] = [flagValue, flag_file]
                    if firstWord == '-cg': 
                        check_groups += [x for x in flagValue.split(',')]
                        if '-cg' in flag_log:
                            flag_log['-cg'].append(flagValue)
                            flag_log['-cg'].append(flag_file)
                        else:
                            flag_log['-cg'] = [flagValue, flag_file]
                    parameter_emails                    = getParameterListFromFile(firstWord, '-pe', flagValue, flag_file, flag_log, parameter_emails)
                    sql_emails                          = getParameterListFromFile(firstWord, '-se', flagValue, flag_file, flag_log, sql_emails)
                    error_emails                        = getParameterListFromFile(firstWord, '-ee', flagValue, flag_file, flag_log, error_emails)
                    catch_all_emails                    = getParameterListFromFile(firstWord, '-ca', flagValue, flag_file, flag_log, catch_all_emails)
                    ignore_checks_for_ca                = getParameterListFromFile(firstWord, '-ic', flagValue, flag_file, flag_log, ignore_checks_for_ca)
                    ignore_checks                       = getParameterListFromFile(firstWord, '-il', flagValue, flag_file, flag_log, ignore_checks)
                    dbases                              = getParameterListFromFile(firstWord, '-dbs', flagValue, flag_file, flag_log, dbases)
     
    #####################   INPUT ARGUMENTS (these would overwrite whats in the configuration file)  #################### 
    email_client                        = getParameterFromCommandLine(sys.argv, '-enc', flag_log, email_client)
    email_sender_address                = getParameterFromCommandLine(sys.argv, '-ens', flag_log, email_sender_address)
    mail_server                         = getParameterFromCommandLine(sys.argv, '-enm', flag_log, mail_server)
    email_sender                        = getParameterListFromCommandLine(sys.argv, '-en', flag_log, email_sender)   #depricated
    hanachecker_interval                = getParameterFromCommandLine(sys.argv, '-hci', flag_log, hanachecker_interval)
    ignore_check_why_set                = getParameterFromCommandLine(sys.argv, '-is', flag_log, ignore_check_why_set)
    active_threads                      = getParameterFromCommandLine(sys.argv, '-at', flag_log, active_threads)
    abap_schema                         = getParameterFromCommandLine(sys.argv, '-abs', flag_log, abap_schema)
    ignore_dublicated_parameter         = getParameterFromCommandLine(sys.argv, '-ip', flag_log, ignore_dublicated_parameter)
    one_email                           = getParameterFromCommandLine(sys.argv, '-oe', flag_log, one_email)
    always_send                         = getParameterFromCommandLine(sys.argv, '-as', flag_log, always_send)
    ssl                                 = getParameterFromCommandLine(sys.argv, '-ssl', flag_log, ssl)
    virtual_local_host                  = getParameterFromCommandLine(sys.argv, '-vlh', flag_log, virtual_local_host)
    dbuserkeys                          = getParameterListFromCommandLine(sys.argv, '-k', flag_log, dbuserkeys)
    std_out                             = getParameterFromCommandLine(sys.argv, '-so', flag_log, std_out)
    out_config                          = getParameterFromCommandLine(sys.argv, '-oc', flag_log, out_config)
    out_dir                             = getParameterFromCommandLine(sys.argv, '-od', flag_log, out_dir)
    check_files                         = getParameterListFromCommandLine(sys.argv, '-mf', flag_log, check_files)
    zip_file                            = getParameterFromCommandLine(sys.argv, '-zf', flag_log, zip_file)
    check_types                         = getParameterListFromCommandLine(sys.argv, '-ct', flag_log, check_types)
    for checkFlagType in ['M', 'I', 'S', 'T', 'C', 'A']: #mini, internal, security, trace, call stacks, ABAP
        for checkFlagNumber in range(1, chidMax):
            checkId = convertToCheckId(checkFlagType, checkFlagNumber)
            if '-'+checkId in sys.argv:
                checkEmailDict[checkFlagType][checkFlagNumber] = [x for x in sys.argv[  sys.argv.index('-'+checkId) + 1   ].split(',')]
                flag_log['-'+checkId] = [sys.argv[  sys.argv.index('-'+checkId) + 1   ], "command line"]
    check_groups                        = getParameterListFromCommandLine(sys.argv, '-cg', flag_log, check_groups)
    parameter_emails                    = getParameterListFromCommandLine(sys.argv, '-pe', flag_log, parameter_emails)
    sql_emails                          = getParameterListFromCommandLine(sys.argv, '-se', flag_log, sql_emails)
    error_emails                        = getParameterListFromCommandLine(sys.argv, '-ee', flag_log, error_emails)
    catch_all_emails                    = getParameterListFromCommandLine(sys.argv, '-ca', flag_log, catch_all_emails)
    ignore_checks_for_ca                = getParameterListFromCommandLine(sys.argv, '-ic', flag_log, ignore_checks_for_ca)
    ignore_checks                       = getParameterListFromCommandLine(sys.argv, '-il', flag_log, ignore_checks)
    dbases                              = getParameterListFromCommandLine(sys.argv, '-dbs', flag_log, dbases)

    ##### SYSTEM ID #############        
    #SID = subprocess.check_output('whoami', shell=True).replace('\n','').replace('adm','').upper()
    SID = run_command('whoami').replace('\n','').replace('adm','').upper()
              
    ############# OUTPUT DIRECTORY #########
    out_dir = out_dir.replace(" ","_").replace(".","_")
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir)
 
    ############# LOG MANAGER ###########
    logman = LogManager(std_out, out_dir, SID)

    ############ CHECK AND CONVERT INPUT PARAMETERS ################ 
    execution_string = " ".join(sys.argv)
    ### std_out, -so
    if not is_integer(std_out):
        log("INPUT ERROR: -so must be an integer. Please see --help for more information.", logman)
        os._exit(1)
    std_out = int(std_out) 
    ### out_config, -oc
    out_config = checkAndConvertBooleanFlag(out_config, "-oc")
    ### email_client, -enc
    if email_client:  # allow to be empty --> no emails are sent --> HANAChecker just used to write critical mini-checks in the log file, with e.g. -ca dummy@dum.com
        if email_client not in ['mailx', 'mail', 'mutt']:
            print("INPUT WARNING: The -enc flag does not specify any of the email clients mailx, mail, or mutt. If you are using an email client that can send emails with the command ")
            print('               <message> | <client> -s "<subject>" \n please let me know.')
            os._exit(1)
    emailSender = None
    if email_client:
        emailSender = EmailSender(email_client, '', '')   #Default we assume -ens and -enm are left empty as default, then configured sender email and server are used
        logman.emailSender = emailSender
    ### email_sender_address, -ens
    if email_sender_address:
        if not is_email(email_sender_address):
            print("INPUT ERROR: The flag -ens must be a valid email. Please see --help for more information.")
            os._exit(1) 
        logman.emailSender.senderEmail = email_sender_address
    ### mail_server, -enm
    if mail_server:
        logman.emailSender.mailServer = mail_server
    ### email_sender (DEPRICATED!), -en
    if email_sender:  # allow to be empty --> no emails are sent --> HANAChecker just used to write critical mini-checks in the log file
        print("WARNING: The flag -en is DEPRICATED! See --help for more information.")
        if not len(email_sender) == 2:
            print("INPUT ERROR: -en requires 2 elements, seperated by a comma. Note: -en is depricated. Please see --help for more information.")
            os._exit(1)
        if not is_email(email_sender[0]):
            print("INPUT ERROR: first element of -en has to be a valid email. Note: -en is depricated. Please see --help for more information.")
            os._exit(1)     
        logman.emailSender.senderEmail = email_sender[0]
        logman.emailSender.mailServer = email_sender[1]
    ### hanachecker_interval, -hci
    if not is_integer(hanachecker_interval):
        log("INPUT ERROR: -hci must be an integer. Please see --help for more information.", logman)
        os._exit(1)
    hanachecker_interval = int(hanachecker_interval)*24*3600  # days to seconds
    ### one_email, -oe
    one_email = checkAndConvertBooleanFlag(one_email, "-oe")
    ### ignore_check_why_set, -is
    ignore_check_why_set = checkAndConvertBooleanFlag(ignore_check_why_set, "-is")    
    ### ignore_dublicated_parameter, -ip
    ignore_dublicated_parameter = checkAndConvertBooleanFlag(ignore_dublicated_parameter, "-ip")
    ### always_send, -as
    always_send = checkAndConvertBooleanFlag(always_send, "-as")
    ### ssl, -ssl
    ssl = checkAndConvertBooleanFlag(ssl, "-ssl")
    hdbsql_string = "hdbsql "
    if ssl:
        hdbsql_string = "hdbsql -e -ssltrustcert -sslcreatecert "
    ### check_files, -mf
    if not check_files and not zip_file:
        print("INPUT ERROR: Either -mf or -zf has to be specified. Please see --help for more information.")
        os._exit(1)
    ### zip_file, -zf
    if zip_file and not check_types:
        print("INPUT ERROR: If -zf is specified also -ct has to be specified. Please see --help for more information.")
        os._exit(1)
    ### check_types, -ct
    if check_types and not zip_file:
        print("INPUT ERROR: If -ct is specified also -zf has to be specified. Please see --help for more information.")
        os._exit(1)
    if check_types:
        for ct in check_types:
            if ct not in ['M', 'I', 'S', 'T', 'P', 'C', 'R', 'A']:
                print("INPUT ERROR: -ct must be a comma seperated list where the elements can only be M, I, S, T, P, C, R, or A. Please see --help for more information.")
                os._exit(1)
        if len(check_types) != len(set(check_types)): # if duplicates
            print("INPUT ERROR: -ct should not contain duplicates. Please see --help for more information.")
            os._exit(1)
    ### active_threads, -at
    if active_threads and not is_number(active_threads):
        log("INPUT ERROR: -at must be a number. Please see --help for more information.", logman)
        os._exit(1)
    if active_threads and not 'C' in check_types:
        print("INPUT ERROR: -at is set allthough there is no C in -ct. Please see --help for more information.")
        os._exit(1)
    ### abap_schema, -abs
    if abap_schema and not 'A' in check_types:
        print("INPUT ERROR: -abs is set allthough there is no A in -ct. Please see --help for more information.")
        os._exit(1)
    if 'A' in check_types and not abap_schema:
        print("INPUT ERROR: There is an A in -ct but -abs is not defined. Please see --help for more information.")
        os._exit(1)
    ### checkEmailDict, -<CHID>
    for checkType, checkNumberEmailDict in checkEmailDict.items():
        for chid, emails in checkNumberEmailDict.items():
            for email in emails:
                if not is_email(email):
                    print("INPUT ERROR, -"+convertToCheckId(checkType, chid)+" is provided a non-valid email. Please see --help for more information.")
                    os._exit(1)
    ### check_groups, -cg
    if len(check_groups)%2:
        print("INPUT ERROR: -cg must be a list with the length of multiple of 2. Please see --help for more information. check_groups = \n", check_groups)
        os._exit(1)
    if len(check_groups):
        if sys.version_info[0] == 2:
            check_groups = [check_groups[i*2:i*2+2] for i in range(len(check_groups)/2)]  # / is integer division in Python 2
        elif sys.version_info[0] == 3:
            check_groups = [check_groups[i*2:i*2+2] for i in range(len(check_groups)//2)]  # // is integer division in Python 3
        else:
            print("ERROR: Wrong Python version")
            os._exit(1)
        try:
            check_groups = [[[cg[0].split('-')[0], cg[0].split('-')[1]], cg[1]] for cg in check_groups]
        except:
            print("INPUT ERROR: -cg must be in the format CHID1-CHID2,email,CHID3-CHID4,email and so on. Please see --help for more information.")
            os._exit(1)
        for cg in check_groups:
            if not is_check_id(cg[0][0]) or not is_check_id(cg[0][1]) or not is_email(cg[1]):
                print("INPUT ERROR: -cg must be in the format CHID1-CHID2,email,CHID3-CHID4,email and so on. Please see --help for more information.")
                os._exit(1)      
            if not get_check_type(cg[0][0]) == get_check_type(cg[0][1]):
                print("INPUT ERROR: the two check IDs in a check group must be of the same check type. Please see --help for more information.")
                os._exit(1)            
        checkEmailDict = addCheckGroupsToDict(checkEmailDict, check_groups)
    ### ignore_checks_for_ca, -ic
    if len(ignore_checks_for_ca) and not len(catch_all_emails):
        print("INPUT ERROR: -ic is specified but not -ca, this makes no sense. Please see --help for more information.")
        os._exit(1)
    for i in range(len(ignore_checks_for_ca)):
        if not is_check_id(ignore_checks_for_ca[i]):
            print("INPUT ERROR: all elements of -ic must be a check id. Please see --help for more information.")
            os._exit(1)
    ### ignore_checks, -il
    for i in range(len(ignore_checks)):
        if not is_check_id(ignore_checks[i]):
            print("INPUT ERROR: all elements of -il must be a check id. Please see --help for more information.")
            os._exit(1)
    ### catch_all_emails, -ca
    if len(catch_all_emails):
        for ca in catch_all_emails:
            if not is_email(ca):
                print("INPUT ERROR: -ca must be in the format email,email,email and so on. Please see --help for more information.")
                os._exit(1)
        checkEmailDict = addCatchAllEmailsToDict(checkEmailDict, catch_all_emails, ignore_checks_for_ca)   
    ### parameter_emails, -pe
    if len(parameter_emails):
        for pe in parameter_emails:
            if not is_email(pe):
                print("INPUT ERROR: -pe must be in the format email,email,email and so on. Please see --help for more information.")
                os._exit(1)     
    parameter_emails.extend(catch_all_emails)   # catch-all-emails also catch parameter critical checks
    ### sql_emails, -se
    if len(sql_emails):
        for se in sql_emails:
            if not is_email(se):
                print("INPUT ERROR: -se must be in the format email,email,email and so on. Please see --help for more information.")
                os._exit(1)     
    sql_emails.extend(catch_all_emails)         # catch-all-emails also catch sql statements with recommendations
    ### error_emails, -ee
    if len(error_emails):
        for ee in error_emails:
            if not is_email(ee):
                print("INPUT ERROR: -ee must be in the format email,email,email and so on. Please see --help for more information.")
                os._exit(1)     
    error_emails.extend(catch_all_emails)         # catch-all-emails also catch the most important HANAChecker errors
    ### dbases, -dbs, and dbuserkeys, -k
    if len(dbases) > 1 and len(dbuserkeys) > 1:
        message = "INPUT ERROR: -k may only specify one key if -dbs is used. Please see --help for more information."
        log_with_emails(message, logman, error_emails)
        os._exit(1)

    ################ START #################
    while True: # hanachecker intervall loop
        for dbuserkey in dbuserkeys:
            checkUserKey(dbuserkey, virtual_local_host, logman, error_emails)
            ############# MULTIPLE DATABASES #######
            for dbase in dbases:
                ############# SQL and LOG MANAGER and CHECK DB CONNECTION ##############
                sqlman = SQLManager(hdbsql_string, dbuserkey, dbase)
                logman.db = dbase
                ping_db(sqlman, logman, error_emails)
                ########## GET MINICHECK FILES FROM -ct if not -mf specified ##############
                if check_types:        
                    tmp_sql_dir = "./tmp_sql_statements/"
                    try:
                        zip_ref = zipfile.ZipFile(zip_file, 'r')
                    except:
                        message = "ERROR: The .zip file is corrupt. Test with e.g. \n python /usr/sap/<SID>/HDB00/exe/Python3/lib/python3.7/zipfile.py -t <zip file>"
                        os._exit(1)
                    zip_ref.extractall(tmp_sql_dir) 
                    [version, revision, mrevision] = hana_version_rev_mrev(sqlman)
                    check_files = getCheckFiles(tmp_sql_dir, check_types, version, revision, mrevision, active_threads, abap_schema)
                #//@audit-info execution code
                ##### GET CRITICAL MINICHECKS FROM ALL MINI-CHECK FILES (either from -ct or -mf) ############
                critical_checks = getCriticalChecks(check_files, ignore_check_why_set, ignore_dublicated_parameter, ignore_checks, sqlman, logman)
                ##### SEND EMAILS FOR ALL CRITICAL MINI-CHECKS THAT HAVE A CORRESPONDING EMAIL ADDRESS ######
                sendEmails(critical_checks, checkEmailDict, parameter_emails, sql_emails, one_email, always_send, check_files, execution_string, out_config, flag_log, logman)
                ########### IF MINICHECK FILES FROM -ct WE HAVE TO CLEAN UP ################
                if check_types:
                    check_files = []           
                    #subprocess.check_output('rm -r '+tmp_sql_dir, shell=True)
                    dummyout = run_command('rm -r '+tmp_sql_dir)
                    zip_ref.close()
        # HANACHECKER INTERVALL
        if hanachecker_interval < 0: 
            sys.exit()
        time.sleep(float(hanachecker_interval))           

          
              
if __name__ == '__main__':
    main()
                        

