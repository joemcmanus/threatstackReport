# threatstackReport
A python script to create daily reports from Threatstack 

This script adds state and simple reporting to the threatstack API. 

It can be run on previous reports or in real time. 

First you would create and inventory. 

    root@foo:~# ./threatstack.py --inventory 
    +----------------------------+-------+
    |           Option           | Value |
    +----------------------------+-------+
    |     Get new inventory      |  True |
    | Get new vulnerability list |  True |
    |        Print report        | False |
    |       Post to Slack        | False |
    |       Slack channel        |  None |
    |       Create Graphs        | False |
    |         Output Dir         |  None |
    +----------------------------+-------+
    DB File Found
    Request returned 200
    Returned 100 agents
    Found pagination token.
    Request returned 200
    Returned 1 agents


Next you would generate a list of vulnerabilities.

    root@foo:~# ./threatstack.py --vulns 
    +----------------------------+-------+
    |           Option           | Value |
    +----------------------------+-------+
    |     Get new inventory      | False |
    | Get new vulnerability list | False |
    |        Print report        | False |
    |       Post to Slack        | False |
    |       Slack channel        |  None |
    |       Create Graphs        | False |
    |         Output Dir         |  None |
    +----------------------------+-------+

Last you can generate reports, graphs and post to slack. 

    root@foo:~# ./threatstack.py --report
    +----------------------------+-------+
    |           Option           | Value |
    +----------------------------+-------+
    |     Get new inventory      | False |
    | Get new vulnerability list | False |
    |        Print report        |  True |
    |       Post to Slack        | False |
    |       Slack channel        |  None |
    |       Create Graphs        | False |
    |         Output Dir         |  None |
    +----------------------------+-------+
    DB File Found
    +-------------+------------------+------------------+
    |             | 2021/06/25 14:39 | 2021/06/25 15:06 |
    +-------------+------------------+------------------+
    |  High CVEs  |        0         |        0         |
    | Medium CVEs |        1         |        1         |
    |   Low CVEs  |        1         |        1         |
    +-------------+------------------+------------------+
    +----------------+----------+------------------+
    |      CVE       | Severity |     Package      |
    +----------------+----------+------------------+
    | CVE-2021-21334 |  medium  | containerd 1.3.3 |
    | CVE-2020-15257 |   low    | containerd 1.3.3 |
    +----------------+----------+------------------+
    +----------------+----------+---------------------------------------+
    |      CVE       | Severity |                 Hosts                 |
    +----------------+----------+---------------------------------------+
    | CVE-2020-15257 |   low    |             foo.example.com           |
    | CVE-2021-21334 |  medium  |             foo2.example.com          |
    |                |          |                 web01                 |
    |                |          |                 web02                 |
    |                |          |                 web03                 |
    |                |          |                 web04                 |
    |                |          |                 web05                 |
    +----------------+----------+---------------------------------------+


Or you could run it all at once :

    root@foo:~# ./threatstack.py --inventory --vulns --report --outdir=threatGraph  --graphs --channel=1234 --slack --token=1234

usage:

    root@foo:~# ./threatstack.py 
    usage: threatstack.py [-h] [--inventory] [--vulns] [--report] [--outdir OUTDIR] [--slack] [--channel CHANNEL] [--token TOKEN] [--graphs]

    Threatstack Daily Report Generator
    
    optional arguments:
      -h, --help         show this help message and exit
      --inventory        Generate inventory
      --vulns            Generate vulnerability list
      --report           Generate report
      --outdir OUTDIR    Output directory for files
      --slack            Post to Slack
      --channel CHANNEL  Slack Channel to post to
      --token TOKEN      Slack bot token, or use OS_ENVIRON
      --graphs           Display graphs where available    

Configuration:
Copy the include threatstack.cfg-example to threatstack.cfg and add your API keye 

    [default]
    tsHost = api.threatstack.com
    tsUserID = 123456789
    tsAPIKey = 123456789
    tsOrgID = 123456789
    dbFile = threatstack.sql3


