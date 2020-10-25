#!/usr/bin/env python3

import sys
from struct import unpack
from io import BytesIO
from time import strftime, gmtime
from argparse import ArgumentParser, RawTextHelpFormatter
from urllib.parse import unquote

__maintainer__ = "Corey Forman"
__original_author__ = "Satishb3"
__source__ = "https://github.com/digitalsleuth/binarycookiereader"
__reference__ = "Script from Satishb3 (http://www.securitylearn.net)"
__version__ = "1.0"
__description__ = "Python3 Parser for the Cookies.binarycookie plist file"
__about__ = \
    "-------------------------------------------------------------------------------------------\n" +\
    "# Safari and iOS applications store their persistent cookies in a binary plist file named #\n" +\
    "# Cookies.binarycookies. This script will dump all of the cookies from this file.         #\n" +\
    "#                                                                                         #\n" +\
    "# This is a Python 3 implementation of the original script found here:                    #\n" +\
    "# https://github.com/as0ler/BinaryCookieReader and here:                                  #\n" +\
    "# http://www.securitylearn.net/2012/10/27/cookies-binarycookies-reader/                   #\n" +\
    "# More information about the format can be found here:                                    #\n" +\
    "# https://github.com/libyal/dtformats/blob/master/documentation/Safari%20Cookies.asciidoc #\n" +\
    "-------------------------------------------------------------------------------------------"

def process(binary_file):
    check_header(binary_file)
    parse_pages(binary_file)
    binary_file.close()

def check_header(binary_file):
    bc_header = b'cook'
    file_header = binary_file.read(4)
    if file_header != bc_header:
        print("Invalid binarycookie header: %s - should start with '0x636f6f6b (cook)' " % str(file_header))
        raise SystemExit(1)
    else:
        pass

def parse_pages(binary_file):
    print("Filename: %s" % args.input_file)
    print("{:12s} {:48s} {:20s} {:12s} {:12s} {:12s} {}".format("Name", "Value", "Domain", "Path", "CreateDate", "ExpiryDate", "Flags"))
    epoch_diff = 978307200                                         #978307200 is the diff between unix epoch and 1/Jan/2001
    num_pages = unpack('>i', binary_file.read(4))[0]               #Number of pages in the binary file: 4 bytes
    page_sizes = []
    for np in range(num_pages):
        page_sizes.append(unpack('>i', binary_file.read(4))[0])    #Each page size: 4 bytes*number of pages
    pages = []
    for ps in page_sizes:
        pages.append(binary_file.read(ps))                         #Grab individual pages and each page will contain at least one cookie
    for page in pages:
        page = BytesIO(page)
        page.read(4)                                               #page header: 4 bytes: Always 00000100
        num_cookies = unpack('<i',page.read(4))[0]                 #Number of cookies in each page, first 4 bytes after the page header in every page.
        cookie_offsets = []
        for nc in range(num_cookies):
            cookie_offsets.append(unpack('<i',page.read(4))[0])    #Every page contains at least one cookie. Fetch cookie starting point from page starting byte
        page.read(4)                                               #end of page header: Always 00000000
        cookie = ''
        for offset in cookie_offsets:
            page.seek(offset)                                      #Move the page pointer to the cookie starting point
            cookiesize = unpack('<i',page.read(4))[0]              #fetch cookie size
            cookie = BytesIO(page.read(cookiesize))
            cookie.read(4)                                         #unknown

            flags = unpack('<i',cookie.read(4))[0]                 #Cookie flags:  1=HTTPS, 4=HTTP, 5=HTTPS and HTTP
            cookie_flags = ''
            if flags==0:
                cookie_flags = 'None'
            elif flags==1:
                cookie_flags = 'HTTPS'
            elif flags==4:
                cookie_flags = 'HTTP'
            elif flags==5:
                cookie_flags = 'HTTPS and HTTP'
            else:
                cookie_flags = 'Unknown Flag'

            unknown = cookie.read(4)                              #unknown
            urloffset = unpack('<i',cookie.read(4))[0]            #cookie domain offset from cookie starting point
            nameoffset = unpack('<i',cookie.read(4))[0]           #cookie name offset from cookie starting point
            pathoffset = unpack('<i',cookie.read(4))[0]           #cookie path offset from cookie starting point
            valueoffset = unpack('<i',cookie.read(4))[0]          #cookie value offset from cookie starting point
            endofcookie = cookie.read(8)                          #end of cookie
            expiry_date_epoch = unpack('<d',cookie.read(8))[0]+epoch_diff          #Expiry date is in Mac epoch format: Starts from 1/Jan/2001
            expiry_date = strftime("%d %b %Y ",gmtime(expiry_date_epoch))[:-1]
            create_date_epoch = unpack('<d',cookie.read(8))[0]+epoch_diff           #Cookies creation time
            create_date = strftime("%d %b %Y ",gmtime(create_date_epoch))[:-1]

            cookie.seek(urloffset-4)                              #fetch domain value from url offset
            url = ''
            u = cookie.read(1)
            while unpack('<b',u)[0]!=0:
                url = url+bytes.decode(u)
                u = cookie.read(1)
            cookie.seek(nameoffset-4)                             #fetch cookie name from name offset
            name = ''
            n = cookie.read(1)
            while unpack('<b',n)[0] != 0:
                name = name+bytes.decode(n)
                if '%' in name:
                    name = unquote(name)
                n = cookie.read(1)
            cookie.seek(pathoffset-4)                            #fetch cookie path from path offset
            path = ''
            pa = cookie.read(1)
            while unpack('<b',pa)[0] != 0:
                path = path+bytes.decode(pa)
                pa = cookie.read(1)
            cookie.seek(valueoffset-4)                           #fetch cookie value from value offset
            value = ''
            va = cookie.read(1)
            while unpack('<b',va)[0] != 0:
                value = value+bytes.decode(va)
                if '%' in value:
                    value = unquote(value)
                va = cookie.read(1)
            print('{:12s} {:48s} {:20s} {:12s} {:12s} {:12s} {}'.format(name, value, url, path, create_date, expiry_date, cookie_flags))

if __name__ == "__main__":
    arg_parse = ArgumentParser(description="Python3 BinaryCookieParser v"+__version__, epilog= str(__about__), formatter_class=RawTextHelpFormatter)
    arg_parse.add_argument("input_file", metavar="<input_file>", help="Input file including path")
    arg_parse.add_argument("-v", action="version", version='%(prog)s' +' v' + str(__version__))
    args = arg_parse.parse_args()

    try:
        binary_file = open(args.input_file,'rb')
        process(binary_file)
    except IOError as e:
        print("Unable to read '%s': %s" %(args.input_file, e), file=sys.stderr)
        raise SystemExit(1)
