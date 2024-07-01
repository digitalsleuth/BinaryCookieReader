# BinaryCookieReader

Original author content found here: http://www.securitylearn.net/2012/10/27/cookies-binarycookies-reader/  
  
This repo was originally forked from: https://github.com/as0ler/BinaryCookieReader and updated for usage with Python 3  
  
Additional information can also be found at: https://github.com/libyal/dtformats/blob/master/documentation/Safari%20Cookies.asciidoc  
Table structure and contents sourced from: https://github.com/Lessica/CookiesTool

## Usage

```bash
usage: binarycookiereader.py [-h] [-p] [-s SORT] [-V] [-v] <input_file>

BinaryCookieReader v2.0

positional arguments:
  <input_file>          Input file including path

optional arguments:
  -h, --help            show this help message and exit
  -p, --pretty          Output into a clean table
  -s SORT, --sort SORT  For pretty mode only: choose to sort by 'name','value','domain','create','expiry','flags'
  -V, --verbose         Verbose mode: include name, value, and flags
  -v, --version         show program's version number and exit

```

## File Format

The binarycookies file is composed of several pages and each page can have one or more cookies.

### File

| Field           | Endianness | Type                 | Size        | Description                             | Sample        |
|-----------------|------------|----------------------|-------------|-----------------------------------------|---------------|
| Magic           | BE         | UTF-8                | 4           | ASCII characters "cook"                 |  63 6F 6F 6B  |
| Number of pages | BE         | Unsigned Int         | 4           |                                         |  00 00 01 96  |
| Page 1 size     | BE         | Unsigned Int         | 4           | Size of Page 1                          |  00 00 00 6F  |

(Repeat for # pages * 4 bytes to get to first page)

### Page

| Field                        | Endianness | Type         | Size          | Description          | Sample        |
|------------------------------|------------|--------------|---------------|----------------------|---------------|
| Header                       | BE         |              | 4             | 0x00000100           |  00 00 01 00  |
| Number of cookies in page    | LE         | Unsigned Int | 4             |                      |  01 00 00 00  |
| Cookie N offset incl. Header | LE         | Unsigned Int | 4             | Repeat for N cookies |  10 00 00 00  |
| Header end                   | LE         |              | 4             | 0x00000000           |  00 00 00 00  |

(Cookie Content Starts)

### Cookie Content

| Field              | Endianness | Type         | Size | Description                                                                  | Sample                    |
|--------------------|------------|--------------|------|------------------------------------------------------------------------------|---------------------------|
| Size               | LE         | Unsigned Int | 4    | Size in bytes                                                                |  5F 00 00 00              |
| Version            | LE         | Unsigned Int | 4    | 0 or 1                                                                       |  00 00 00 00              |
| Flags              | LE         | Bit field    | 4    | isSecure = 1, isHTTPOnly = 1 << 2, unknown1 = 1 << 3, unknown2 = 1 << 4      |  01 00 00 00              |
| Has port           | LE         | Unsigned Int | 4    | 0 or 1                                                                       |  00 00 00 00              |
| URL Offset         | LE         | Unsigned Int | 4    | Offset from the start of the cookie                                          |  38 00 00 00              |
| Name Offset        | LE         | Unsigned Int | 4    | Offset from the start of the cookie                                          |  4C 00 00 00              |
| Path Offset        | LE         | Unsigned Int | 4    | Offset from the start of the cookie                                          |  5B 00 00 00              |
| Value Offset       | LE         | Unsigned Int | 4    | Offset from the start of the cookie                                          |  5D 00 00 00              |
| Comment Offset     | LE         | Unsigned Int | 4    | Offset from the start of the cookie, 0x00000000 if not present               |  00 00 00 00              |
| Comment URL Offset | LE         | Unsigned Int | 4    | Offset from the start of the cookie, 0x00000000 if not present               |  00 00 00 00              |
| Expiration         | LE         | Double       | 8    | Number of seconds since 00:00:00 UTC on 1 January 2001                       |  00 00 00 AD 5A 07 C8 41  |
| Creation           | LE         | Double       | 8    | Number of seconds since 00:00:00 UTC on 1 January 2001                       |  00 00 00 5A B2 42 BD 41  |
| Port               | LE         | Unsigned Int | 2    | Only present if the "Has port" field is 1                                    |                           |
| Comment            | LE         | String       |      | Null-terminated, optional                                                    |                           |
| Comment URL        | LE         | String       |      | Null-terminated, optional                                                    |                           |
| URL                | LE         | String       |      | Null-terminated                                                              |  www.knowwhere.com        |
| Name               | LE         | String       |      | Null-terminated                                                              |  _guages_unique.          |
| Path               | LE         | String       |      | Null-terminated                                                              |  /                        |
| Value              | LE         | String       |      | Null-terminated                                                              |  .                        |

### End of File

| Field           | Endianness | Type                 | Size        | Description                             | Sample                    |
|-----------------|------------|----------------------|-------------|-----------------------------------------|---------------------------|
| Checksum        | BE         | Unsigned Int         | 4           | Sum every 4th byte for each page        |  00 00 2F F2              |
| Footer          | BE         |                      | 8           | 0x07172005000000(45\|4b)                |  07 17 20 05 00 00 00 45  |
| Metadata        |            | Binary Property List | TO EOF      | Contains NSHTTPCookieAcceptPolicy value |  62 70 6C 69 73 74 30 30  |
