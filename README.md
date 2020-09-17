# New! Exploit Scan for CVE-2020-1472 (ZeroLogon)

Scan DCs in your network to detect *actual* exploitation of CVE-2020-1472

Examples:
```
python scan.py -vuln CVE-2020-1472 -target-file targets.txt
python scan.py -vuln CVE-2020-1472 -target <DC name/IP>
```

Tool works by trying an empty password for DCs every minute. Since exploitation must set password to an empty one, unless reverted very quickly this will detect exploitation attempts if running during exploitation.

# NTLM scanner

Checks for various NTLM vulnerabilities over SMB.
The script will establish a connection to the target host(s) and send
an invalid NTLM authentication. If this is accepted, the host is vulnerable to
the applied NTLM vulnerability and you can execute the relevant NTLM attack.
More details in:
- https://www.preempt.com/blog/how-to-easily-bypass-epa-to-compromise-any-web-server-that-supports-windows-integrated-authentication/
- https://www.preempt.com/blog/your-session-key-is-my-session-key-how-to-retrieve-the-session-key-for-any-authentication/
- https://www.preempt.com/blog/drop-the-mic-cve-2019-1040/
- https://www.preempt.com/blog/drop-the-mic-2-active-directory-open-to-more-ntlm-attacks/

Note most scans do not generate failed login attempts as the login information itself is valid. CVE-2019-1338 does generate
a failed authentication and might cause an account lockout.

Software is based on the following:
- CVE-2019-1040 scanner (https://github.com/fox-it/cve-2019-1040-scanner) by Dirk-jan Mollema (@_dirkjan)
- Impacket (https://github.com/SecureAuthCorp/impacket) by SecureAuth Corporation (https://www.secureauth.com/)

# Usage
The script requires a recent impacket version. Should work with both python 2 and 3 (Python 3 requires you to use impacket from git).

```
[*] NTLM vulnerabilities scanner by @YaronZi / Preempt - Based on impacket by SecureAuth
usage: scan.py [-h] [-target TARGET] [-target-file file]
               [-port [destination port]] [-vuln [scanned vulnerability]]
               [-hashes LMHASH:NTHASH]

NTLM scanner - Connects over SMB and attempts to authenticate with invalid
NTLM packets. If accepted, target is vulnerable to the scanned vulnerability

optional arguments:
  -h, --help            show this help message and exit
  -target TARGET        [[domain/]username[:password]@]<targetName or address>

connection:
  -target-file file     Use the targets in the specified file instead of the
                        one on the command line (you must still specify
                        something as target name)
  -port [destination port]
                        Destination port to connect to SMB Server
  -vuln [scanned vulnerability]
                        The vulnerability to scan SMB Server on [CVE-2019-1019
                        |CVE-2019-1040|CVE-2019-1166|CVE-2019-1338|CVE-2020-14
                        72]

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
```
