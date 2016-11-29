''' ============================================================================================
Copyright (c) 2016 Devon Ackerman

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.

Coder: Devon Ackerman
Email: devon@aeiforensics.com
Social: @aei4n6
Created: 2016.10.12 
Updated: 2016.11.29

Description: Python program for decoding different types base64 string data discovered during 
Intrusion Response (IR) events.  This tool assumes the use of the standard alphabet: 
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=
Have a custom alphabet?  For now, try: http://malwaretracker.com/decoder_base64.php

v0.1: (complete) level 1 for simple base64 decode function
v0.2: (complete) level 2 for simple base64 decode function as ASCII
v0.3: (complete) level 3 for base64 decode + gzip decompress
v0.4: (complete) level 4 for base64 decode -> machine code
v0.5: (complete) added a menu system to receive input from user to select which routine to execute

Future: 
 + error handling
 + feed base64 string from prompt (or) input file & eliminate hard coded base64 string
 + export output > .txt file

============================================================================================ '''

# Modules
import os         # operating system
import sys        #
import gzip       # For Level 3
import base64     # Underlying structure dependency
import StringIO   # For Level 3
import binascii   # For Level 4

# Base64 string to be pasted below within/between quotes
encoded_data = "base64_string_here"

def menu():
    strs = ('Enter 1 -> simple base64 decode\n'
            'Enter 2 -> simple base64 decode as ASCII\n'
            'Enter 3 -> base64 decode + gzip string\n'
            'Enter 4 -> base64 decode -> machineCode \n'
            'Enter 5 to exit : ')
    choice = raw_input(strs)
    return int(choice) 

while True:          #use while True
    choice = menu()
    if choice == 1:
        
        # Level 1 - Print statement for simple base64 decode
       
        print "Base64 string is", len(encoded_data),"characters (in legth)."
        print "====================================================="
        print "Decoded base64 is below..."
        print "base64 decode:\t\t",       base64.b64decode(encoded_data)
        print 
        print         
        
    elif choice == 2:

        # Level 2 - Print statement for simple base64 decode as ASCII
       
        print "Base64 string is", len(encoded_data),"characters (in legth)."
        print "====================================================="
        print "Decoded base64 as ASCII is below..."
        print "base64 decode (ASCII):\t", base64.b64decode(encoded_data).decode('ascii')
        print 
        print         


    elif choice == 3:
        
        # Level 3 - Print statement for base64 encoded + gzip compressed string
       
        gzip_string = base64.b64decode(encoded_data)
        print "Encoded Data Character Count:\t\t\t", len(encoded_data)
        print "Encoded Data (Compressed gzip) Character Count:\t", len(gzip_string)
        string_in = StringIO.StringIO(gzip_string)
        gzip_data = gzip.GzipFile(fileobj=string_in)
        string_out = gzip_data.read()       
        print "Base64 string is", len(encoded_data),"characters (in legth)."
        print "====================================================="
        print "Decoded base64 + gzip string below..."
        print "====================================================="
        print string_out[:]
        print 
        print         
        
    elif choice == 4:
        
        '''
        Level 4 - Print statement for base64 decoded -> machineCode
        Tip: Take output from Level 4 and drop into hexed.it website (drop-down box on 'Insert clipboard data'
        window properly detects the output from this program as 'Hexadecimal Values')
        
        Take data from the following type of instance and decode into HEX notation
        [Byte[]]$fQ2 = [System.Convert]::FromBase64String("....")
        
        Alternatively, a user can take the above string in its entirety and copy/paste to PowerShell.
        The type of the $vp9 variable is a byte array (byte[]). If entered as above into PowerShell, then the $vp9 variable
        will contain the un-Base64'd string.  From there, the user can execute the following command: 
        [System.BitConverter]::ToString($vp9)
        This will take the contents of the byte array, separated by - , and print in HEX notation
        '''

        machineCode = binascii.a2b_base64(encoded_data)    
        print "Base64 string is", len(encoded_data),"characters (in legth)."
        print "====================================================="
        print "Decoded base64 to machine code (HEX) below..."
        print 
        print "-".join("{:02X}".format(ord(c)) for c in machineCode)
        print 
        print 

    elif choice == 5:
        break