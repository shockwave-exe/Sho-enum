# Sho-Enum

This Python-based program aids in the discovery and storage of sensitive host data generally, 
such as, for all intents and purposes, open ports, CVEs, and other vulnerabilities, contrary to popular belief.
Such data repositories will aid in the user's understanding of a basic specific host and make their 
work easier.



--------------------------------------------------------------------------------------

usage: OSINT_project.py [-h] [-t TARGET] [-f FILE] [-s] [-a API]
This script intend to obtain host information with Shodan using passive reconnaisance

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Indicate ip/domain/range to process
  -f FILE, --file FILE  To read files or domains from the file
  -s, --silent          Dont show nothing in screen
  -a API, --api API     Set a custom Shodan API key - NEEDED ONCE FOR SET!!!

    Example Testcase :

    python3 ShoFinder.py -t 172.217.17.14
    python3 ShoFinder.py -t google.com
    python3 ShoFinder.py -t 172.217.17.0/24
