# satellite-host-cve

A script to list CVE's that are either installable or applicable for a host (or all hosts) within one organization. Altough Satellite6 gives a nice way to handle errata, there are customers who need to have a view based on CVE's and not on security errata.

# What does code do

It lists all CVE's for a host, mapped across it's lifecycle path. It also list what the related errata's are. See example output below.

# What versions does it work on

This script has been tested and works on:

* Satellite 6.2 BETA on RHEL 7.2

# Prerequisites

* python >= 2.7.11
* python module argparse installed
* python module request installed
* A login user to Satellite with read access to the organization

# How to run your code

~~~
./satellite-host-cve.py --help
usage: satellite-host-cve.py [-h] [-u USERNAME] [-p PASSWORD] [-n SERVER]
                             [-o ORGANIZATION] [-w HOST] [-x]

Satellite CVE Reporter

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Username to access Satellite (defaults to admin
  -p PASSWORD, --password PASSWORD
                        Password to access Satellite (asked if not given)
  -n SERVER, --server SERVER
                        Satellite server (defaults to localhost)
  -o ORGANIZATION, --organization ORGANIZATION
                        Organization (defaults to 1)
  -w HOST, --host HOST  Show only CVE's for this host (all if not given)
  -x, --no-ssl-verify   Disable SSL verification

~~~

# Example Output

~~~
./satellite-host-cve.py -u admin -n sat62ga.lab1.local -w t1.lab1.local -x
Password: 

CVE's for host t1.lab1.local on content view CCV_TEST in lifecycle environment QA

CVE            Synced -> Library -> DEV -> QA       In errata
------------------------------------------------------------------
CVE-2015-2328    I                         I        RHSA-2016:1025
CVE-2015-3197    A                                  RHSA-2016:0301
CVE-2015-3217    I                         I        RHSA-2016:1025
CVE-2015-3256    A                                  RHSA-2016:0189
CVE-2015-4792    A                                  RHSA-2016:0534
CVE-2015-4802    A                                  RHSA-2016:0534
CVE-2015-4815    A                                  RHSA-2016:0534
CVE-2015-4816    A                                  RHSA-2016:0534
CVE-2015-4819    A                                  RHSA-2016:0534
CVE-2015-4826    A                                  RHSA-2016:0534
CVE-2015-4830    A                                  RHSA-2016:0534
CVE-2015-4836    A                                  RHSA-2016:0534
CVE-2015-4858    A                                  RHSA-2016:0534
CVE-2015-4861    A                                  RHSA-2016:0534
CVE-2015-4870    A                                  RHSA-2016:0534
CVE-2015-4879    A                                  RHSA-2016:0534
CVE-2015-4913    A                                  RHSA-2016:0534
CVE-2015-5073    I                         I        RHSA-2016:1025
CVE-2015-5157    A                                  RHSA-2016:0185
CVE-2015-5229    A                                  RHSA-2016:0176
CVE-2015-7547    A                                  RHSA-2016:0176
CVE-2015-7575    A                                  RHSA-2016:0008,RHSA-2016:0007,RHSA-2016:0012
CVE-2015-7872    A                                  RHSA-2016:0185
CVE-2015-7979    I                         I        RHSA-2016:1141
CVE-2015-8138    A                                  RHSA-2016:0063
CVE-2015-8385    I                         I        RHSA-2016:1025
CVE-2015-8386    I                         I        RHSA-2016:1025
CVE-2015-8388    I                         I        RHSA-2016:1025
CVE-2015-8391    I                         I        RHSA-2016:1025
CVE-2015-8629    A                                  RHSA-2016:0532
CVE-2015-8630    A                                  RHSA-2016:0532
CVE-2015-8631    A                                  RHSA-2016:0532
CVE-2016-0505    A                                  RHSA-2016:0534
CVE-2016-0546    A                                  RHSA-2016:0534
CVE-2016-0596    A                                  RHSA-2016:0534
CVE-2016-0597    A                                  RHSA-2016:0534
CVE-2016-0598    A                                  RHSA-2016:0534
CVE-2016-0600    A                                  RHSA-2016:0534
CVE-2016-0606    A                                  RHSA-2016:0534
CVE-2016-0608    A                                  RHSA-2016:0534
CVE-2016-0609    A                                  RHSA-2016:0534
CVE-2016-0616    A                                  RHSA-2016:0534
CVE-2016-0642    A                                  RHSA-2016:0534
CVE-2016-0651    A                                  RHSA-2016:0534
CVE-2016-0702    A                                  RHSA-2016:0301
CVE-2016-0705    A                                  RHSA-2016:0301
CVE-2016-0728    A                                  RHSA-2016:0064
CVE-2016-0758    A                                  RHSA-2016:1033
CVE-2016-0777    A                                  RHSA-2016:0043
CVE-2016-0778    A                                  RHSA-2016:0043
CVE-2016-0787    A                                  RHSA-2016:0428
CVE-2016-0797    A                                  RHSA-2016:0301
CVE-2016-0799    I                         I        RHSA-2016:0722
CVE-2016-0800    A                                  RHSA-2016:0301
CVE-2016-1547    I                         I        RHSA-2016:1141
CVE-2016-1548    I                         I        RHSA-2016:1141
CVE-2016-1550    I                         I        RHSA-2016:1141
CVE-2016-1908    A                                  RHSA-2016:0465
CVE-2016-1950    A                                  RHSA-2016:0370
CVE-2016-1978    A                                  RHSA-2016:0685
CVE-2016-1979    A                                  RHSA-2016:0685
CVE-2016-2047    A                                  RHSA-2016:0534
CVE-2016-2105    I                         I        RHSA-2016:0722
CVE-2016-2106    I                         I        RHSA-2016:0722
CVE-2016-2107    I                         I        RHSA-2016:0722
CVE-2016-2108    I                         I        RHSA-2016:0722
CVE-2016-2109    I                         I        RHSA-2016:0722
CVE-2016-2518    I                         I        RHSA-2016:1141
CVE-2016-2842    I                         I        RHSA-2016:0722
CVE-2016-3115    A                                  RHSA-2016:0465
CVE-2016-3191    I                         I        RHSA-2016:1025

~~~

# Known issues

* it uses argparse and not optparse. argparse is not present in the standard RHEL6 repositories, afaik.
