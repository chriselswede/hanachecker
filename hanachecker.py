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
    print(" -ip     ignore dublicated parameter, parameters that are set to same value in different layers will only be mentioned once, default true           ")
    print(" -oe     one email [true/false], true: only one email is sent per email address, false: one email is sent per critical mini check, default: false   ")
    print(" -as     always send [true/false], true: all email addresses will be send at least a notification email, even if none of the mini-checks assigned   ")
    print("         to the emails were potential critical, default: false                                                                                      ")
    print(" -ca     catch all emails, the email addresses specified by the -ca flag recieve an email about each potential critical mini-check (also from       ")
    print("         parameter checks, if any), default: '' (not used)                                                                                          ")
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
    print("         Example:  -ct M,I,S,T,P,C,R   (in this example all possible mini-check types; mini, internal, security, trace, parameter, call stacks,     ")
    print("                                        and SQL recommendations would be executed)                                                                  ")
    print(" -ff     flag file, full path to a file that contains input flags, each flag in a new line, all lines in the file that does not start with a        ")
    print("         flag are considered comments,                                                      default: '' (not used)                                  ")
    print("         *** OUTPUT ***                                                                                                                             ")
    print(" -od     output directory, full path of the folder where the log files will end up (if not exist it will be created),                               ")
    print("         default: '/tmp/hanachecker_output'                                                                                                         ")
    print(" -so     standard out switch, 1: write to std out, 0: do not write to std out, default:  1                                                          ")
    print("         *** EMAIL ***                                                                                                                              ")
    print(" -en     email notification, <sender's email>,<mail server>                                                                                         ") 
    print("                             example: me@ourcompany.com,smtp.intra.ourcompany.com                                                                   ")
    print('         NOTE: For this to work you have to install the linux program "sendmail" and add a line similar to DSsmtp.intra.ourcompany.com in the file  ')
    print("               sendmail.cf in /etc/mail/, see https://www.systutorials.com/5167/sending-email-using-mailx-in-linux-through-internal-smtp/           ")
    print("         NOTE: If you do not specify this no emails will be sent --> HANAChecker is then used just to write the log file --> could be used          ")
    print("               together with the -ca flag to write to file all potential critical mini-checks                                                       ")
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
    print(" EXAMPLE: python hanachecker.py -zf SQLStatements.zip -ct M -en chris@comp.com,smtp.intra.comp.com -M1142 chris@du.my,lena@du.my -M1150 per@du.my,lena@du.my -as true -oe true ")
    print("                                                                                                                                                    ")
    print(" TODO: test                                                                                                                                         ")
    print("       CALL SYS.STATISTICSSERVER_SENDMAIL_DEV('SMTP',25,'emailfrom',’emailto1,emailto2','Test mail from HANA system subject','Test body from HANA, body',?); ")
    print("       Implement the -en, -ens as I implemented it in HANASitter ... nicer there                                                                    ")
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

######################## DEFINE CLASSES ##################################

class EmailSender:
    def __init__(self, senderEmail, mailServer):
        self.senderEmail = senderEmail
        self.mailServer = mailServer
    def printEmailSender(self):
        print "Sender Email: ", self.senderEmail, " Mail Server: ", self.mailServer 

class MiniCheck:
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
        print self.summary()
        
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
        sum += "This SQL statement is of type "+self.Type+", originates from "+self.Origin+", and executed by the "+self.Engine+" engine."
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
    command_run = subprocess.check_output(['/bin/bash', '-i', '-c', "alias "+alias])
    pieces = command_run.strip("\n").strip("alias "+alias+"=").strip("'").strip("cd ").split("/")
    path = ''
    for piece in pieces:
        if piece[0] == '$':
            piece = (subprocess.check_output(['/bin/bash', '-i', '-c', "echo "+piece])).strip("\n")
        path = path + '/' + piece + '/' 
    return path       
        
def checkUserKey(dbuserkey, virtual_local_host, logman, error_emails):
    try: 
        key_environment = subprocess.check_output('''hdbuserstore LIST '''+dbuserkey, shell=True) 
        if "NOT FOUND" in key_environment:
            message = "ERROR, the key "+dbuserkey+" is not maintained in hdbuserstore."
            log_with_emails(message, logman, error_emails)
            os._exit(1)
    except:
        message = "ERROR, the key "+dbuserkey+" is not maintained in hdbuserstore."
        log_with_emails(message, logman, error_emails)
        os._exit(1)
    local_host = subprocess.check_output("hostname", shell=True).replace('\n','') if virtual_local_host == "" else virtual_local_host
    ENV = key_environment.split('\n')[1].replace('  ENV : ','').split(',')
    key_hosts = [env.split(':')[0] for env in ENV]
    if not local_host in key_hosts:
        message = "ERROR, local host, "+local_host+", should be one of the hosts specified for the key, "+dbuserkey+" (in case of virtual, please use -vlh, see --help for more info)"
        log_with_emails(message, logman, error_emails)
        os._exit(1)    
    
def checkAndConvertBooleanFlag(boolean, flagstring):     
    boolean = boolean.lower()
    if boolean not in ("false", "true"):
        print "INPUT ERROR: ", flagstring, " must be either 'true' or 'false'. Please see --help for more information."
        os._exit(1)
    boolean = True if boolean == "true" else False
    return boolean
        
def convertToCheckId(checkType, checkNumber):
    return checkType+'0'*(4-len(str(checkNumber)))+str(checkNumber)        
        
def is_check_id(checkString):
    if not len(checkString) == 5:
        return False
    if checkString[0] not in ['M', 'I', 'S', 'T', 'C']:
        return False
    if not is_integer(checkString[1:5].lstrip('0')):
        return False
    return True
    
def get_check_type(checkString):
    if not is_check_id(checkString):
        print "ERROR: checkString, "+checkString+", in get_check_type is not a check ID"
        os._exit(1)
    return checkString[0]
    
def get_check_number(checkString):
    if not is_check_id(checkString):
        print "ERROR: checkString in get_check_numer is not a check ID"
        os._exit(1)
    return int(checkString[1:5].lstrip('0'))
        
def log(message, logman, file_name = "", recieversEmail = ""):
    logMessage = '"'+message+'"' 
    if logman.emailSender:    
        logMessage += " is sent to " + recieversEmail if recieversEmail else message
    if logman.std_out:
        print logMessage
    if file_name == "":
        file_name = "hanacheckerlog"
    logfile = open(logman.out_dir+"/"+file_name+"_"+datetime.now().strftime("%Y-%m-%d_%H-%M-%S"+".txt").replace(" ", "_"), "a")
    logfile.write(logMessage+"\n")   
    logfile.flush()
    logfile.close()
    if recieversEmail:
        if logman.emailSender:
            #MAILX (https://www.systutorials.com/5167/sending-email-using-mailx-in-linux-through-internal-smtp/):
            mailstring = 'echo "'+message.replace('"','')+'" | mailx -s "HANAChecker: Potential Critical Situation(s) '+logman.db+"@"+logman.SID+'!" -S smtp=smtp://'+logman.emailSender.mailServer+' -S from="'+logman.emailSender.senderEmail+'" '+recieversEmail
            #print mailstring
            subprocess.check_output(mailstring, shell=True)

def log_with_emails(message, logman, error_emails):
    if error_emails:
        for error_email in error_emails:
            log(message, logman, recieversEmail = error_email)
    else:
        log(message, logman)

def hana_version_revision(sqlman):
    command_run = subprocess.check_output(sqlman.hdbsql_jAU + " \"select value from sys.m_system_overview where name = 'Version'\"", shell=True)
    hanaver = command_run.splitlines(1)[2].split('.')[0].replace('| ','')
    hanarev = command_run.splitlines(1)[2].split('.')[2]
    #hanamrev = command_run.splitlines(1)[2].split('.')[3]   #We dont need the maintenence revision
    if not is_integer(hanarev):
        print "ERROR: something went wrong checking hana revision."
        os._exit(1)
    return [int(hanaver), int(hanarev)]

def get_file_revision_number_str(file_name, base_file_name, tmp_sql_dir):
    if '+' not in file_name:
        file_revision = '0'
    else:
        file_revision = file_name.split(tmp_sql_dir+base_file_name+'_')[1].split('+')[0] 
        if not file_revision:
            file_revision = '0'
        file_revision = file_revision.split('.')
        if len(file_revision) >= 3:
            file_revision = file_revision[0]+file_revision[1]+file_revision[2]  #hopefully we never need to care about maintanance revision 
    return file_revision 

def get_revision_number_str(version, revision):
    if revision < 10:
        revision_str = '0000'+str(revision)
    elif revision < 100:
        revision_str = '000'+str(revision)
    return str(version)+revision_str                   
        
def getFileVersion(base_file_name, tmp_sql_dir, version, revision):
    revision_number_str = get_revision_number_str(version, revision)
    try:
        output = subprocess.check_output('ls '+tmp_sql_dir+base_file_name+'_[12]* '+tmp_sql_dir+base_file_name+'.txt', shell=True, stderr=subprocess.STDOUT) #removes SHC
    except Exception, e:
        output = str(e.output)
    output = output.splitlines(1)
    files = [f.strip('\n') for f in output if not 'cannot access' in f]
    if len(files) == 0:
        print "ERROR: There were no on-premise files found with name "+base_file_name+", files = ", files
        os._exit(1)
    chosen_file_name = files[0] 
    for file_name in files:
        file_revision_number_str = get_file_revision_number_str(file_name, base_file_name, tmp_sql_dir)
        choosen_file_revision_number_str = get_file_revision_number_str(chosen_file_name, base_file_name, tmp_sql_dir)
        if int(file_revision_number_str) <= int(revision_number_str) and int(choosen_file_revision_number_str) < int(file_revision_number_str):
            chosen_file_name = file_name
    return chosen_file_name

def getCheckFiles(tmp_sql_dir, check_types, version, revision, active_threads):
    check_files = []
    for ct in check_types:
        if ct == 'M':
            check_files.append(getFileVersion('HANA_Configuration_MiniChecks', tmp_sql_dir, version, revision))    
        elif ct == 'I':
            check_files.append(getFileVersion('HANA_Configuration_MiniChecks_Internal', tmp_sql_dir, version, revision))
        elif ct == 'S':
            check_files.append(getFileVersion('HANA_Security_MiniChecks', tmp_sql_dir, version, revision))
        elif ct == 'T':
            check_files.append(getFileVersion('HANA_TraceFiles_MiniChecks', tmp_sql_dir, version, revision))
        elif ct == 'P':
            check_files.append(getFileVersion('HANA_Configuration_Parameters', tmp_sql_dir, version, revision))
        elif ct == 'C':
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
        try:
            result = subprocess.check_output(sqlman.hdbsql_jAaxU + ' -I '+check_file, shell=True).splitlines()
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
                    if line[4] == 'R':
                        sql_hash = line[1]
                        if not hash_is_dublicate(sql_hash, sqls_with_recommendation):
                            sql_type = line[2]
                            origin = line[3]
                            engine = line[4] 
                            sqls_with_recommendation.append(SQLWithRecommendation(sql_hash, sql_type, origin, engine))
                elif is_check_id(line[1]):
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
                        else: 
                            potential_critical = line[6] if checkType in ['M','I'] else line[5] #'M' and 'I' column 6, but for 'S' column 5
                            if potential_critical == 'X':
                                checkId = line[1] if line[1] else old_checkId
                                description = line[2] if line[2] else old_description
                                host = line[3] if checkType in ['M','I'] else ''    #no host for 'S'
                                value = line[4] if checkType in ['M','I'] else line[3]
                                expected_value = line[5] if checkType in ['M','I'] else line[4]
                                sap_note = line[7] if checkType in ['M','I'] else line[6]
                                critical_mini_checks.append(MiniCheck(checkId, '', description, host, '', '', '', '', value, expected_value, potential_critical, sap_note, ''))
                            old_checkId = line[1] if line[1] else old_checkId
                            old_description = line[2] if line[2] else old_description    
    return [critical_mini_checks, critical_parameter_checks, sqls_with_recommendation]
    
def ping_db(sqlman, logman, error_emails):
    with open(os.devnull, 'w') as devnull:  # just to get no stdout in case HANA is offline
        try:
            command_run = subprocess.check_output(sqlman.hdbsql_jAaxU + ' "select * from dummy"', shell=True, stderr=devnull).splitlines(1)
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
    for checkType in ['M', 'I', 'S', 'T', 'C']: #mini, internal, security, trace, call stacks
        for checkNumber in range(1, chidMax):
            if convertToCheckId(checkType, checkNumber) not in ignore_checks_for_ca:
                if checkNumber in list(checkEmailDict[checkType].keys()):
                    for ca_email in catch_all_emails:
                        if ca_email not in checkEmailDict[checkType][checkNumber]:
                            checkEmailDict[checkType][checkNumber].append(ca_email)
                else:
                    checkEmailDict[checkType][checkNumber] = catch_all_emails  
    return checkEmailDict
    
def sendEmails(critical_checks, checkEmailDict, parameter_emails, sql_emails, one_email, always_send, execution_string, logman):
    critical_mini_checks = critical_checks[0]
    critical_parameter_checks = critical_checks[1]
    sqls_with_recommendation = critical_checks[2]
    messages = {}
    dbstring = ""
    if len(logman.db) > 1:
        dbstring = logman.db+'@' 
    if always_send:
        unique_emails = []
        for val in checkEmailDict.values():
            for emails in val.values():
                for email in emails:
                    if email not in unique_emails:
                        unique_emails.append(email)
        always_send_message = "HANAChecker was executed "+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+" on "+dbstring+logman.SID+" with \n"+execution_string+"\nIf any of the mini and/or parameter checks that you are responsible for seem critical, you will be notified now.\n"
        for email in unique_emails:
            messages.update({email:[always_send_message]})
        for email in parameter_emails:
            if email not in unique_emails:
                messages.update({email:[always_send_message]})
        for email in sql_emails:
            if email not in unique_emails:
                messages.update({email:[always_send_message]})
    for check in critical_mini_checks:
        if check.Number in list(checkEmailDict[check.Type].keys()):
            for email in checkEmailDict[check.Type][check.Number]:
                if email in messages:
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
    for email, messages_for_email in messages.items():
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
    if sys.version_info[0] != 2 or sys.version_info[1] != 7:
        print "VERSION ERROR: hanacleaner is only supported for Python 2.7.x. Did you maybe forget to log in as <sid>adm before executing this?"
        os._exit(1)

    #####################   DEFAULTS   ####################
    email_sender = []
    hanachecker_interval = -1
    ignore_check_why_set = "false"
    active_threads = ''
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
    out_dir = "/tmp/hanachecker_output"
    flag_file = ""    #default: no configuration input file
    check_files = None
    zip_file = None
    check_types = None
    checkEmailDict = {'M':{}, 'I':{}, 'S':{}, 'T':{}, 'C':{}}  #mini, internal, security, trace, call stack
    check_groups = []
    parameter_emails = []
    sql_emails = []
    error_emails = []
    catch_all_emails = []
    ignore_checks_for_ca = []
    ignore_checks = []

    
    #####################  CHECK INPUT ARGUMENTS #################
    if len(sys.argv) == 1:
        print "INPUT ERROR: hanachecker needs input arguments. Please see --help for more information."
        os._exit(1) 
    if len(sys.argv) != 2 and len(sys.argv) % 2 == 0:
        print "INPUT ERROR: Wrong number of input arguments. Please see --help for more information."
        os._exit(1)
    for i in range(len(sys.argv)):
        if i % 2 != 0:
            if sys.argv[i][0] != '-':
                print "INPUT ERROR: Every second argument has to be a flag, i.e. start with -. Please see --help for more information."
                os._exit(1)    
    
    #####################   PRIMARY INPUT ARGUMENTS   ####################     
    if '-h' in sys.argv or '--help' in sys.argv:
        printHelp() 
    if '-d' in sys.argv or '--disclaimer' in sys.argv:
        printDisclaimer() 
    if '-ff' in sys.argv:
        flag_file = sys.argv[sys.argv.index('-ff') + 1]
     
    ############ CONFIGURATION FILE ###################
    if flag_file:
        with open(flag_file, 'r') as fin:
            for line in fin:
                firstWord = line.strip(' ').split(' ')[0]  
                if firstWord[0:1] == '-':
                    flagValue = line.strip(' ').split('"')[1].strip('\n').strip('\r') if line.strip(' ').split(' ')[1][0] == '"' else line.strip(' ').split(' ')[1].strip('\n').strip('\r')
                    if firstWord == '-en': 
                        email_sender = [x for x in flagValue.split(',')]                    
                    if firstWord == '-hci':
                        hanachecker_interval = flagValue
                    if firstWord == '-is': 
                        ignore_check_why_set = flagValue
                    if firstWord == '-at': 
                        active_threads = flagValue 
                    if firstWord == '-ip': 
                        ignore_dublicated_parameter = flagValue   
                    if firstWord == '-oe': 
                        one_email = flagValue
                    if firstWord == '-as': 
                        always_send = flagValue
                    if firstWord == '-ssl': 
                        ssl = flagValue
                    if firstWord == '-vlh':
                        virtual_local_host = flagValue
                    if firstWord == '-k':
                        dbuserkeys = [x for x in flagValue.split(',')]
                    if firstWord == '-so': 
                        std_out = flagValue
                    if firstWord == '-od': 
                        out_dir = flagValue
                    if firstWord == '-mf': 
                        check_files = [x for x in flagValue.split(',')]
                    if firstWord == '-zf': 
                        zip_file = flagValue
                    if firstWord == '-ct': 
                        check_types = [x for x in flagValue.split(',')]
                    for checkFlagType in ['M', 'I', 'S', 'T', 'C']: #mini, internal, security, trace, call stack
                        for checkFlagNumber in range(1, chidMax):
                            checkId = convertToCheckId(checkFlagType, checkFlagNumber)
                            if firstWord == '-'+checkId:
                                checkEmailDict[checkFlagType][checkFlagNumber] = [x for x in flagValue.split(',')]
                    if firstWord == '-cg': 
                        check_groups = [x for x in flagValue.split(',')]
                    if firstWord == '-pe': 
                        parameter_emails = [x for x in flagValue.split(',')]
                    if firstWord == '-se': 
                        sql_emails = [x for x in flagValue.split(',')]
                    if firstWord == '-ee': 
                        error_emails = [x for x in flagValue.split(',')]
                    if firstWord == '-ca': 
                        catch_all_emails = [x for x in flagValue.split(',')]
                    if firstWord == '-ic': 
                        ignore_checks_for_ca = [x for x in flagValue.split(',')]
                    if firstWord == '-il': 
                        ignore_checks = [x for x in flagValue.split(',')]
                    if firstWord == '-dbs':
                        dbases = [x for x in flagValue.split(',')]
                        

     
    #####################   INPUT ARGUMENTS (these would overwrite whats in the configuration file)  #################### 
    if '-en' in sys.argv:
        email_sender = [x for x in sys.argv[  sys.argv.index('-en') + 1   ].split(',')] 
    if '-hci' in sys.argv:
        hanachecker_interval = sys.argv[sys.argv.index('-hci') + 1]
    if '-is' in sys.argv:
        ignore_check_why_set = sys.argv[sys.argv.index('-is') + 1]
    if '-at' in sys.argv:
        active_threads = sys.argv[sys.argv.index('-at') + 1]
    if '-ip' in sys.argv:
        ignore_dublicated_parameter = sys.argv[sys.argv.index('-ip') + 1]        
    if '-oe' in sys.argv:
        one_email = sys.argv[sys.argv.index('-oe') + 1]
    if '-as' in sys.argv:
        always_send = sys.argv[sys.argv.index('-as') + 1]
    if '-ssl' in sys.argv:
        ssl = sys.argv[sys.argv.index('-ssl') + 1]
    if '-vlh' in sys.argv:
        virtual_local_host = sys.argv[sys.argv.index('-vlh') + 1]
    if '-k' in sys.argv:
        dbuserkeys = [x for x in sys.argv[  sys.argv.index('-k') + 1   ].split(',')]
    if '-so' in sys.argv:
        std_out = int(sys.argv[sys.argv.index('-so') + 1])
    if '-od' in sys.argv:
        out_dir = sys.argv[sys.argv.index('-od') + 1]
    if '-mf' in sys.argv:
        check_files = [x for x in sys.argv[  sys.argv.index('-mf') + 1   ].split(',')]
    if '-zf' in sys.argv:
        zip_file = sys.argv[sys.argv.index('-zf') + 1]
    if '-ct' in sys.argv:
        check_types = [x for x in sys.argv[  sys.argv.index('-ct') + 1   ].split(',')]
    for checkFlagType in ['M', 'I', 'S', 'T', 'C']: #mini, internal, security, trace, call stacks
        for checkFlagNumber in range(1, chidMax):
            checkId = convertToCheckId(checkFlagType, checkFlagNumber)
            if '-'+checkId in sys.argv:
                checkEmailDict[checkFlagType][checkFlagNumber] = [x for x in sys.argv[  sys.argv.index('-'+checkId) + 1   ].split(',')] 
    if '-cg' in sys.argv:
        check_groups = [x for x in sys.argv[  sys.argv.index('-cg') + 1   ].split(',')]
    if '-pe' in sys.argv:
        parameter_emails = [x for x in sys.argv[  sys.argv.index('-pe') + 1   ].split(',')]
    if '-se' in sys.argv:
        sql_emails = [x for x in sys.argv[  sys.argv.index('-se') + 1   ].split(',')]
    if '-ee' in sys.argv:
        error_emails = [x for x in sys.argv[  sys.argv.index('-ee') + 1   ].split(',')]
    if '-ca' in sys.argv:
        catch_all_emails = [x for x in sys.argv[  sys.argv.index('-ca') + 1   ].split(',')]
    if '-ic' in sys.argv:
        ignore_checks_for_ca = [x for x in sys.argv[  sys.argv.index('-ic') + 1   ].split(',')]
    if '-il' in sys.argv:
        ignore_checks = [x for x in sys.argv[  sys.argv.index('-il') + 1   ].split(',')]
    if '-dbs' in sys.argv:
        dbases = [x for x in sys.argv[  sys.argv.index('-dbs') + 1   ].split(',')]
            
    ##### SYSTEM ID #############        
    SID = subprocess.check_output('whoami', shell=True).replace('\n','').replace('adm','').upper()
              
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
    ### email_sender, -en
    if email_sender:  # allow to be empty --> no emails are sent --> HANAChecker just used to write critical mini-checks in the log file
        if not len(email_sender) == 2:
            print "INPUT ERROR: -en requires 2 elements, seperated by a comma. Please see --help for more information."
            os._exit(1)
        if not is_email(email_sender[0]):
            print "INPUT ERROR: first element of -en has to be a valid email. Please see --help for more information."
            os._exit(1) 
    emailSender = None
    if email_sender:
        emailSender = EmailSender(email_sender[0], email_sender[1])
        logman.emailSender = emailSender
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
        print "INPUT ERROR: Either -mf or -zf has to be specified. Please see --help for more information."
        os._exit(1)
    ### zip_file, -zf
    if zip_file and not check_types:
        print "INPUT ERROR: If -zf is specified also -ct has to be specified. Please see --help for more information."
        os._exit(1)
    ### check_types, -ct
    if check_types and not zip_file:
        print "INPUT ERROR: If -ct is specified also -zf has to be specified. Please see --help for more information."
        os._exit(1)
    if check_types:
        for ct in check_types:
            if ct not in ['M', 'I', 'S', 'T', 'P', 'C', 'R']:
                print "INPUT ERROR: -ct must be a comma seperated list where the elements can only be M, I, S, T, P, C, or R. Please see --help for more information."
                os._exit(1)
        if len(check_types) != len(set(check_types)): # if duplicates
            print "INPUT ERROR: -ct should not contain duplicates. Please see --help for more information."
            os._exit(1)
    ### active_threads, -at
    if active_threads and not is_number(active_threads):
        log("INPUT ERROR: -at must be a number. Please see --help for more information.", logman)
        os._exit(1)
    if active_threads and not 'C' in check_types:
        print "INPUT ERROR: -at is set allthough there is no C in -ct. Please see --help for more information."
        os._exit(1)
    ### checkEmailDict, -<CHID>
    for checkType, checkNumberEmailDict in checkEmailDict.items():
        for chid, emails in checkNumberEmailDict.items():
            for email in emails:
                if not is_email(email):
                    print "INPUT ERROR, -"+convertToCheckId(checkType, chid)+" is provided a non-valid email. Please see --help for more information."
                    os._exit(1)
    ### check_groups, -cg
    if len(check_groups)%2:
        print "INPUT ERROR: -cg must be a list with the length of multiple of 2. Please see --help for more information. check_groups = \n", check_groups
        os._exit(1)
    if len(check_groups):
        check_groups = [check_groups[i*2:i*2+2] for i in range(len(check_groups)/2)]
        try:
            check_groups = [[[cg[0].split('-')[0], cg[0].split('-')[1]], cg[1]] for cg in check_groups]
        except:
            print "INPUT ERROR: -cg must be in the format CHID1-CHID2,email,CHID3-CHID4,email and so on. Please see --help for more information."
            os._exit(1)
        for cg in check_groups:
            if not is_check_id(cg[0][0]) or not is_check_id(cg[0][1]) or not is_email(cg[1]):
                print "INPUT ERROR: -cg must be in the format CHID1-CHID2,email,CHID3-CHID4,email and so on. Please see --help for more information."
                os._exit(1)      
            if not get_check_type(cg[0][0]) == get_check_type(cg[0][1]):
                print "INPUT ERROR: the two check IDs in a check group must be of the same check type. Please see --help for more information."
                os._exit(1)            
        checkEmailDict = addCheckGroupsToDict(checkEmailDict, check_groups)
    ### ignore_checks_for_ca, -ic
    if len(ignore_checks_for_ca) and not len(catch_all_emails):
        print "INPUT ERROR: -ic is specified but not -ca, this makes no sense. Please see --help for more information."
        os._exit(1)
    for i in range(len(ignore_checks_for_ca)):
        if not is_check_id(ignore_checks_for_ca[i]):
            print "INPUT ERROR: all elements of -ic must be a check id. Please see --help for more information."
            os._exit(1)
    ### ignore_checks, -il
    for i in range(len(ignore_checks)):
        if not is_check_id(ignore_checks[i]):
            print "INPUT ERROR: all elements of -il must be a check id. Please see --help for more information."
            os._exit(1)
    ### catch_all_emails, -ca
    if len(catch_all_emails):
        for ca in catch_all_emails:
            if not is_email(ca):
                print "INPUT ERROR: -ca must be in the format email,email,email and so on. Please see --help for more information."
                os._exit(1)
        checkEmailDict = addCatchAllEmailsToDict(checkEmailDict, catch_all_emails, ignore_checks_for_ca)   
    ### parameter_emails, -pe
    if len(parameter_emails):
        for pe in parameter_emails:
            if not is_email(pe):
                print "INPUT ERROR: -pe must be in the format email,email,email and so on. Please see --help for more information."
                os._exit(1)     
    parameter_emails.extend(catch_all_emails)   # catch-all-emails also catch parameter critical checks
    ### sql_emails, -se
    if len(sql_emails):
        for se in sql_emails:
            if not is_email(se):
                print "INPUT ERROR: -se must be in the format email,email,email and so on. Please see --help for more information."
                os._exit(1)     
    sql_emails.extend(catch_all_emails)         # catch-all-emails also catch sql statements with recommendations
    ### error_emails, -ee
    if len(error_emails):
        for ee in error_emails:
            if not is_email(ee):
                print "INPUT ERROR: -ee must be in the format email,email,email and so on. Please see --help for more information."
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
                    zip_ref = zipfile.ZipFile(zip_file, 'r')
                    zip_ref.extractall(tmp_sql_dir) 
                    [version, revision] = hana_version_revision(sqlman)
                    check_files = getCheckFiles(tmp_sql_dir, check_types, version, revision, active_threads)
                ##### GET CRITICAL MINICHECKS FROM ALL MINI-CHECK FILES (either from -ct or -mf) ############
                critical_checks = getCriticalChecks(check_files, ignore_check_why_set, ignore_dublicated_parameter, ignore_checks, sqlman, logman)
                ##### SEND EMAILS FOR ALL CRITICAL MINI-CHECKS THAT HAVE A CORRESPONDING EMAIL ADDRESS ######
                sendEmails(critical_checks, checkEmailDict, parameter_emails, sql_emails, one_email, always_send, execution_string, logman)
                ########### IF MINICHECK FILES FROM -ct WE HAVE TO CLEAN UP ################
                if check_types:
                    check_files = []           
                    subprocess.check_output('rm -r '+tmp_sql_dir, shell=True)
                    zip_ref.close()
        # HANACHECKER INTERVALL
        if hanachecker_interval < 0: 
            sys.exit()
        time.sleep(float(hanachecker_interval))           

          
              
if __name__ == '__main__':
    main()
                        

