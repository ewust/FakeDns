FakeDns
=======

This is a fork of Crypt0s's FakeDns, with a time-based rebind feature added.

The old functionality is left, and it would be nice to merge this feature into the config-file interface eventually, but WIP and all that.

Time-based Rebind
======

Rebinding based off the number of requests can be unreliable due to browser
speculation, prefetching and caching. Instead, we use a time-based rebind
mechanism, where for each client IP (and each unique domain) is given a
"primary" IP as a result for the first N seconds, no matter how many requests
they make during that time. Once the timer expires, the rebind (secondary) IP
address is returned.

We also encode the secondary IP in the domain name, in little-endian order. So
if we are rebinding on the domain test.example.com, we can have a client
lookup 1.0.168.192.test.example.com. After the timeout, FakeDns will provide
clients a response containing 192.168.0.1.

    USAGE:
    ./fakedns.py --primary-ip 6.6.6.6 --domain test.example.com --timeout 55



OldDocs
======

A python regular-expression based DNS server!

    USAGE:
    ./fakedns.py [-h] -c Config path [-i interface IP address] [--rebind]

The dns.conf should be set the following way:

    [RECORD TYPE CODE] [python regular expression] [answer] [rebind answer]

The answer could be a ip address or string `self`,
the `self` syntax sugar will be translated to your current machine's local ip address, such as `192.168.1.100`.

If a match is not made, the DNS server will attempt to resolve the request using whatever you have your DNS server set to on your local machine and will proxy the request to that server on behalf of the requesting user.

Supported Request Types
=======================
    - A
    - TXT
    - AAAA

In-Progress Request Types
=========================
    - MX
    - PTR
    - CNAME

Misc
====
    - Supports DNS Rebinding


DNS Rebinding
=============

FakeDNS can support a DNS rebinding attack through the --rebind flag.  This flag will log each rule match from each client and will respond with the first address/entry the first time, and the second address/entry on every subsequent request.
    
