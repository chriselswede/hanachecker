# HANAChecker  
A monitoring script to automatically execute the SAP HANA's mini-checks and send alert emails

### DESCRIPTION:  
The HANAChecker executes SQL: "HANA_Configuration_MiniChecks" (See SAP Note [1969700](https://launchpad.support.sap.com/#/notes/=1969700) and SAP Note [1999993](https://launchpad.support.sap.com/#/notes/=1999993)). For every "potential critical" mini-check, i.e. where the column C has an X, it sends out an email to the email address specified for that particular mini-check. This can run "forever" with a specified interval. See also SAP Note [1999993](https://launchpad.support.sap.com/#/notes/=1999993).

### DISCLAIMER:   
ANY USAGE OF HANACHECKER ASSUMES THAT YOU HAVE UNDERSTOOD AND AGREED THAT:  
1. HANAChecker is NOT SAP official software, so normal SAP support of HANAChecker cannot be assumed  
2. HANAChecker is open source  
3. HANAChecker is provided "as is"  
4. HANAChecker is to be used on "your own risk"  
5. HANAChecker is a one-man's hobby (developed, maintained and supported only during non-working hours)  
6. HANAChecker expects "default" HANA environment with no modifications done in the .bashrc or other files
8. All HANAChecker documentations have to be read and understood before any usage:  
* The .pdf file hanachecker.pdf  
* All output from executing    `python hanachecker.py --help`  
9. HANAChecker is not providing any recommendations, all flags shown in the documentation (see point 6.) are only examples
