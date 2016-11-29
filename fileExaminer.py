'''
Copyright (c) 2014 Chet Hosmer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.
'''

# basecode by Chet Hosmer
# 0.1 fork by Peter White       (Added code to peel off first 16 bytes and last 16 bytes of a file    
#                                 for purposes of easily identifying file header and footer signatures. )
# 0.2 update by Devon Ackerman  (Script formatting changes throughout + output formatting changes    	)
# 0.3 update by Devon Ackerman  (Implemented SHA256 as part of output + activated existing MD5 code  	)
# 0.4 update by Devon Ackerman  (Added bytes formatting to output for file size                      	)
# 0.5 update by Devon Ackerman  (Added HEX and ASCII line formatting to output for readability       	)

import os       # Python Standard Library OS Module
import time     # Python Standard Library Time Module
import hashlib  # Python Standard Library Hashing Methods

# Class: FileExaminer Class
#
# Desc: Handles all methods related to File Based Forensics
# Methods  constructor:    Initializes the Forensic File Object and Collects Basic Attributes
#                          File Size
#                          MAC Times
#                          Reads file into a buffer
#          hashFile:       Generates the selected one-way hash of the file
#          destructor:     Deletes the Forensic File Object

class FileExaminer:

    # Constructor

    def __init__(self, theFile):

        #Attributes of the Object

        self.lastError   = "OK"
        self.mactimes    = ["","",""]
        self.fileSize    = 0
        self.fileType    = "unknown"
        self.uid         = 0
        self.gid         = 0
        self.mountPoint  = False
        self.fileRead    = False
        self.md5         = ""
        self.sha1        = ""  # Group A adding new hashing capability
        self.sha256      = ""  # Group A adding new hashing capability
        self.headerBytes = ""  # Group A defining new variable
        self.footerBytes = ""  # Group A defining new variable
        self.headerHex   = ""  # Group A defining new variable
        self.footerHex   = ""  # Group A defining new variable

        try:

            if os.path.exists(theFile):
                # get the file statistics
                theFileStat =  os.stat(theFile)

                # get the MAC Times and store them in a list

                self.macTimes = []
                self.macTimes.append(time.ctime(theFileStat.st_mtime))
                self.macTimes.append(time.ctime(theFileStat.st_atime))
                self.macTimes.append(time.ctime(theFileStat.st_ctime))

                # get and store the File size

                self.fileSize = theFileStat.st_size

                # Get and store the ownership information

                self.uid = theFileStat.st_uid
                self.gid = theFileStat.st_gid

                if os.path.isfile(theFile):
                    self.fileType = "File"
                # Is this a real file?
                elif os.path.islink(theFile):
                    self.fileType = "Link"
                # Is This filename actually a directory?
                elif os.path.isdir(theFile):
                    self.fileType = "Directory"
                else:
                    self.fileType = "Unknown"

                # Is the pathname a mount point?
                if os.path.ismount(theFile):
                    self.mountPoint = True
                else:
                    self.mountPoint = False        

                # Is the file Accessible for Read?

                if os.access(theFile, os.R_OK) and self.fileType == "File":

                    # Open the file
                    fp = open(theFile, 'rb')

                    # Assume we have enough space 
                    self.buffer = fp.read()

                    # Close the file we have the entire file in memory
                    fp.close()

                    self.fileRead = True

                else:
                    self.fileRead = False

            else:
                self.lastError = "File does not exist"

        except:
            self.lastError = "File Exception Raised"       

    # partially completed hash file method

    def hashFile(self,hashType):

    # Support for MD5, SHA1, and SHA256 hashing

        try:

            if hashType == "MD5":
                hashObj = hashlib.md5()
                hashObj.update(self.buffer)
                self.md5 = hashObj.hexdigest().upper()
                self.lastError = "OK"
                return True
            elif hashType == "SHA1":
                hashObj = hashlib.sha1()
                hashObj.update(self.buffer)
                self.sha1 = hashObj.hexdigest().upper()
                self.lastError = "OK"
                return True
            elif hashType == "SHA256":
                hashObj = hashlib.sha256()
                hashObj.update(self.buffer)
                self.sha256 = hashObj.hexdigest().upper()
                self.lastError = "OK"
                return True	    
            else:
                self.lastError = "Invalid Hash Type Specified"
                return False
        except:
            self.lastError = "File Hash Failure"
            return False

        # Function to pull off 16 bytes from the beginning and ending of the file

    def SignatureOfFile(self):

        # header and footer | 16 byte length reads

        self.headerBytes = str(self.buffer[0:16])

        self.footerBytes = str(self.buffer[-16:])

        # Format the header and footer bytes in 0x00        

        for byte in FEobj.headerBytes:
            self.headerHex+=format(ord(byte),'02x')
            self.headerHex+=" "

        for byte in FEobj.footerBytes:               
            self.footerHex+=format(ord(byte),'02x')
            self.footerHex+=" "

        return True

    def __del__(self):
        print "closed"

# End Forensic File Class ====================================

#
# ------ MAIN SCRIPT STARTS HERE -----------------
#

if __name__ == '__main__':

    # The file is set to 'image.jpg' in the local directory within the script; change as appropriate

    print "File Examainer Object Test \n"

    FEobj = FileExaminer("./image.jpg")

    if FEobj.lastError == "OK":

        print "MAC  Times: ", FEobj.macTimes
        print "File  Size:  {:,}".format(FEobj.fileSize), "bytes"
        print "Owner ID:   ", FEobj.uid
        print "Group ID:   ", FEobj.gid
        print "File  Type: ", FEobj.fileType
        print "Mount Point:", FEobj.mountPoint
        print "File Read:  ", FEobj.fileRead

        # Expansion of existing code to confirm that all functions executed with Return true, 
        # where the file hash is output.  The if statement runs if the file signature function returns True
        # and then prints out the variables that were set up by the function SignatureofFile()

        if FEobj.fileRead:
            if FEobj.hashFile("MD5"):
                print "MD5:        ", FEobj.md5                		
            else:
                print FEobj.lastError
            if FEobj.hashFile("SHA1"):
                print "SHA1:       ", FEobj.sha1
            else:
                print FEobj.lastError
            if FEobj.hashFile("SHA256"):
                print "SHA256:     ", FEobj.sha256
            else:
                print FEobj.lastError	    

            if FEobj.SignatureOfFile():
                # Output the file's header
                print
                print "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII"
                print "---------------------------------------------------------------------------------"
                # Print Header HEX and Header ASCII                  
                print FEobj.headerHex, FEobj.headerBytes 
                # Print Footer HEX and Footer ASCII       
                print FEobj.footerHex, FEobj.footerBytes
                print "\n"

            else:
                print FEobj.lastError

        del FEobj

    else:
        print "Last Error: ", FEobj.lastError