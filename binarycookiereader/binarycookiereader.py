#!/usr/bin/env python3

import sys
from struct import unpack
from io import BytesIO
from datetime import datetime as dt
from argparse import ArgumentParser, RawTextHelpFormatter
from urllib.parse import unquote
from pathlib import Path
from prettytable import *

__maintainer__ = "Corey Forman"
__original_author__ = "Satishb3"
__source__ = "https://github.com/digitalsleuth/binarycookiereader"
__reference__ = "Script from Satishb3 (http://www.securitylearn.net)"
__version__ = "2.0"
__date__ = "30 June 2024"
__description__ = "Python 3 Parser for the Cookies.binarycookie plist file"
__about__ = (
    "Safari and iOS applications store their persistent cookies in a binary plist file named  \n"
    + "Cookies.binarycookies. This script will dump all of the cookies from this file.      \n\n"
    + "This is a Python 3 implementation of the original script found here:                 \n\n"
    + "https://github.com/as0ler/BinaryCookieReader and here:                                 \n"
    + "http://www.securitylearn.net/2012/10/27/cookies-binarycookies-reader/                \n\n"
    + "More information about the format can be found here:                                   \n"
    + "https://github.com/libyal/dtformats/blob/master/documentation/Safari%20Cookies.asciidoc\n"
    + "and https://github.com/digitalsleuth/BinaryCookieReader/blob/master/FORMAT.md       \n \n"
)


def process(binary_file, file_size, all_args):
    check_header(binary_file)
    parse_pages(binary_file, file_size, all_args)
    binary_file.close()


def check_header(binary_file):
    bc_header = b"cook"
    file_header = binary_file.read(4)
    if file_header != bc_header:
        print(
            f"Invalid binarycookie header: {file_header} - should start with '0x636f6f6b (cook)'"
        )
        raise SystemExit(1)
    else:
        pass


def parse_pages(binary_file, file_size, all_args):
    verbose = all_args["verbose"]
    table = all_args["table"]
    tbl_output = []
    csv_output = []
    print(f"Filename: {Path(all_args['input_file']).resolve()}\n")
    if verbose:
        csv_output.append(["Name,Value,Domain and Path,Create Date,Expiry Date,Flags"])
        tbl_output.append(
            ["Name", "Value", "Domain and Path", "Create Date", "Expiry Date", "Flags"]
        )
    else:
        csv_output.append(["Domain and Path,Create Date,Expiry Date"])
        tbl_output.append(["Domain and Path", "Create Date", "Expiry Date"])
    epoch_diff = 978307200  # 978307200 is the diff between unix epoch and 1/Jan/2001
    bplist_offset = 8
    num_pages = unpack(">i", binary_file.read(4))[
        0
    ]  # Number of pages in the binary file: 4 bytes
    bplist_offset += num_pages * 4
    page_sizes = []
    for np in range(num_pages):
        page_size = unpack(">i", binary_file.read(4))[0]
        page_sizes.append(page_size)  # Each page size is 4 bytes * number of pages
        bplist_offset += page_size
    pages = []
    for ps in page_sizes:
        pages.append(
            binary_file.read(ps)
        )  # Grab individual pages and each page will contain at least one cookie
    for page in pages:
        page = BytesIO(page)
        page.read(4)  # Page header: 4 bytes: Always 0x00000100
        num_cookies = unpack("<i", page.read(4))[
            0
        ]  # Number of cookies in each page, first 4 bytes after the page header in every page.
        cookie_offsets = []
        for nc in range(num_cookies):
            cookie_offsets.append(
                unpack("<i", page.read(4))[0]
            )  # Every page contains at least one cookie. Fetch cookie starting point from page starting byte
        page.read(4)  # End of page header: Always 00000000
        cookie = ""
        for offset in cookie_offsets:
            page.seek(offset)  # Move the page pointer to the cookie starting point
            cookiesize = unpack("<i", page.read(4))[0]  # Fetch cookie size
            cookie = BytesIO(page.read(cookiesize))
            cookie.read(4)

            flags = unpack("<i", cookie.read(4))[
                0
            ]  # Cookie flags:  1=HTTPS, 4=HTTP, 5=HTTPS and HTTP
            cookie_flags = ""
            if flags == 0:
                cookie_flags = "None"
            elif flags == 1:
                cookie_flags = "HTTPS"
            elif flags == 4:
                cookie_flags = "HTTP"
            elif flags == 5:
                cookie_flags = "HTTPS and HTTP"
            else:
                cookie_flags = "Unknown Flag"

            has_port = cookie.read(4)  # If the cookie has a port assigned
            urloffset = unpack("<i", cookie.read(4))[
                0
            ]  # Cookie domain offset from cookie starting point
            nameoffset = unpack("<i", cookie.read(4))[
                0
            ]  # Cookie name offset from cookie starting point
            pathoffset = unpack("<i", cookie.read(4))[
                0
            ]  # Cookie path offset from cookie starting point
            valueoffset = unpack("<i", cookie.read(4))[
                0
            ]  # Cookie value offset from cookie starting point
            endofcookie = cookie.read(8)  # End of cookie
            expiry_date_epoch = (
                unpack("<d", cookie.read(8))[0] + epoch_diff
            )  # Expiry date is in Mac epoch format: Starts from 1/Jan/2001
            create_date_epoch = (
                unpack("<d", cookie.read(8))[0] + epoch_diff
            )  # Cookie creation time

            cookie.seek(urloffset - 4)  # Fetch domain value from url offset
            url = ""
            u = cookie.read(1)
            while unpack("<b", u)[0] != 0:
                url = url + bytes.decode(u)
                u = cookie.read(1)
            cookie.seek(nameoffset - 4)  # Fetch cookie name from name offset
            name = ""
            n = cookie.read(1)
            while unpack("<b", n)[0] != 0:
                name = name + bytes.decode(n)
                if "%" in name:
                    name = unquote(name)
                n = cookie.read(1)
            cookie.seek(pathoffset - 4)  # Fetch cookie path from path offset
            path = ""
            pa = cookie.read(1)
            while unpack("<b", pa)[0] != 0:
                path = path + bytes.decode(pa)
                pa = cookie.read(1)
            cookie.seek(valueoffset - 4)  # Fetch cookie value from value offset
            value = ""
            va = cookie.read(1)
            while unpack("<b", va)[0] != 0:
                value = value + bytes.decode(va)
                if "%" in value:
                    value = unquote(value)
                va = cookie.read(1)
            if verbose:
                csv_output.append(
                    [
                        f"{name},{value},{url}{path},{int(create_date_epoch)},{int(expiry_date_epoch)},{cookie_flags}"
                    ]
                )
                tbl_output.append(
                    [
                        f"{name}",
                        f"{value}",
                        f"{url}{path}",
                        f"{int(create_date_epoch)}",
                        f"{int(expiry_date_epoch)}",
                        f"{cookie_flags}",
                    ]
                )
            else:
                csv_output.append(
                    [f"{url}{path},{int(create_date_epoch)},{int(expiry_date_epoch)}"]
                )
                tbl_output.append(
                    [
                        f"{url}{path}",
                        f"{int(create_date_epoch)}",
                        f"{int(expiry_date_epoch)}",
                    ]
                )
    bplist_offset += 12  # 4 bytes for the checksum, 8 bytes for the footer signature
    if all_args["bplist"] and file_size > bplist_offset:
        binary_file.seek(bplist_offset)
        if binary_file.read(8) == b"bplist00":
            binary_file.seek(bplist_offset)
            bplist = binary_file.read(file_size - bplist_offset)
            bplist_file = open(f"{all_args['input_file']}.bplist", "wb")
            bplist_file.write(bplist)
            bplist_file.close()
    if all_args["bplist"] and file_size <= bplist_offset:
        print("--bplist was selected, but there is no bplist at the end of the file")
    if table:
        tbl = PrettyTable(tbl_output[0])
        tbl.set_style(SINGLE_BORDER)
        tbl.align = "l"
        tbl.add_rows(tbl_output[1:])
        sort_by = "Domain and Path"
        if all_args["sort"]:
            sort_col = (all_args["sort"]).lower()
            if "name" in sort_col:
                sort_by = "Name"
            elif "value" in sort_col:
                sort_by = "Value"
            elif "domain" in sort_col:
                sort_by = "Domain and Path"
            elif "create" in sort_col:
                sort_by = "Create Date"
            elif "expiry" in sort_col:
                sort_by = "Expiry Date"
            elif "flags" in sort_col:
                sort_by = "Flags"
        if not sort_by in tbl.field_names:
            print(
                f"{sort_by} is not available in this view, defaulting to sort by 'Domain and Path'"
            )
            sort_by = "Domain and Path"
        tbl.sortby = sort_by
        tbl.custom_format["Create Date"] = lambda f, v: dt.utcfromtimestamp(
            int(v)
        ).strftime("%Y-%m-%d %H:%M:%S")
        tbl.custom_format["Expiry Date"] = lambda f, v: dt.utcfromtimestamp(
            int(v)
        ).strftime("%Y-%m-%d %H:%M:%S")
        print(tbl)
    else:
        for each_entry in csv_output:
            print(",".join(each_entry))


def main():
    arg_parse = ArgumentParser(
        description="BinaryCookieReader v" + __version__,
        epilog=str(__about__),
        formatter_class=RawTextHelpFormatter,
    )
    arg_parse.add_argument(
        "input_file", metavar="<input_file>", help="Input file including path"
    )
    arg_parse.add_argument(
        "-b",
        "--bplist",
        dest="bplist",
        action="store_true",
        help="If a bplist exists at the end of the .binarycookies file, export it as <filename>.bplist",
    )
    arg_parse.add_argument(
        "-t",
        "--table",
        dest="table",
        action="store_true",
        help="Output into a clean table",
    )
    arg_parse.add_argument(
        "-s",
        "--sort",
        dest="sort",
        help="For table output only: choose to sort by 'name','value','domain','create','expiry','flags'",
    )
    arg_parse.add_argument(
        "-V",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Verbose mode: include name, value, and flags",
    )
    arg_parse.add_argument(
        "-v",
        "--version",
        action="version",
        version="%(prog)s" + " v" + str(__version__),
    )
    args = arg_parse.parse_args()
    all_args = vars(args)
    try:
        binary_file = open(all_args["input_file"], "rb")
        file_size = Path(all_args["input_file"]).stat().st_size
        process(binary_file, file_size, all_args)
    except IOError as e:
        print(f"Unable to read '{args.input_file}': {e}")
        raise SystemExit(1)

if __name__ == "__main__":
    main()
