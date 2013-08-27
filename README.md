check_iftraffic_nrpe.py
=======================

This is a Nagios plugin to check network traffic with NRPE on Linux.
This script has been created because I like writing Python scripts.

Note that only myself tested this script so far. Feedbacks are very welcome.

Prerequisites
-------------

* Python 2.x
* The python-argparse library

Compatibility
-------------

This script has been tested under Python 2.x only.
I don't know if it works unders Python 3.

This script has been tested under Nagios 3.x only.
I have no idea how it behaves with older versions.

Usage examples
--------------

How to get some help:

    check_iftraffic_nrpe.py --help

Query all interfaces except the loopback interface:

    check_iftraffic_nrpe.py -x lo

Query only eth1:

    check_iftraffic_nrpe.py -i eth1

Set warning value to 80% (default: warning=85, critical=98):

    check_iftraffic_nrpe.py -w 80

Define a Gigabit interface (the value must be in bytes):

    check_iftraffic_nrpe.py --bandwidth=131072000


Authors
-------
Copyright 2012 Van Dyck Sven <mobilesvenvd@gmail.com> (original perl version)
Copyright 2012-2013 Samuel Krieg <my_first_name.my_last_name at gmail dot com>
Copyright 2013 Cygnus Networks GmbH <info@cygnusnetworks.de>

Van Dyck Sven did not specify a license for his works. According to the GitHub
terms of serivce the author implicitly allow anyone to view and fork his
sources. The contributions of `*@cygnusnetworks.de` are licensed under the
MIT/X11 license in the hopes that all authors license their works under a
compatible license such as GPL. The contributions from Samuel Krieg have been
licensed under the GPLv3 license.
