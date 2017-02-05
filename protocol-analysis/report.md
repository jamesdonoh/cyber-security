---
title: Cyber Security Coursework - Protocol Analysis
author: James Donohue - <james.donohue@bbc.co.uk>
---

# Introduction

This is my report for the 'protocol analysis' part of the Cyber Security coursework assignment.

The third-party tools used in this report were:

- `file(1)` - command-line tool common on UNIX-based systems for identifying file types
- Wireshark v2.2.4 - graphical network protocol analyser

## `capture1.pcap`

The `file` tool identifies this capture as follows:

    tcpdump capture file (little-endian) - version 2.4 (Ethernet, capture length 65535)

From this we can learn that the capture was created on a little-endian processor (such as the Intel x86 family). The 'capture length' indicates that captured data was limited to 65535 bytes per packet [@wireshark].

Opening the file in Wireshark shows it contains 44 packets. Using the *Statistics > Endpoints* report we can see the packets relate to 6 different Ethernet addresses and 5 IPv4 addresses.

### Find the username & password from the HTTP Basic type of authentication

By using the `http` view filter in Wireshark to show only HTTP packets (see Figure \ref{capture1-http}) we can see two separate HTTP connections are made from host `192.168.0.3` to port 80 on host `192.168.0.1`. The first of these connections contains a single request (`GET /`) which results in a `401 Access Denied` response.

![Wireshark filtering for only HTTP packets in capture1.pcap\label{capture1-http}](capture1-http.png){ width=50% }

The second connection (coloured in purple on Figure \ref{capture1-http}) contains two requests made using HTTP Basic authentication. The content of these requests can be seen most easily using the *Follow > TCP Stream` feature (see Figure \ref{capture1-auth}).

![Wireshark Follow TCP Stream showing HTTP Basic authentication in capture1.pcap\label{capture1-auth}](capture1-auth.png){ width=50% }

Basic HTTP authentication, originally specified in HTTP/1.0, allows for simple challenge-response authentication of web clients using the `Authorization` header. The value after the scheme name `Basic` is a Base64 encoding of the username and password, separated by a colon. As no encryption is performed on the password, the Basic scheme is explicitly non-secure [@rfc1945]. In this case the client sends the following header:

    Authorization: Basic YWRtaW5pc3RyYXRvcjpwQHNzdzByZA==

The server responds with `HTTP/1.1 200 OK`, indicating that the authentication attempt was successful. The plaintext of the Base64 value can easily be determined using a trivial fragment of Python:

    >>> import base64
    >>> encoded = 'YWRtaW5pc3RyYXRvcjpwQHNzdzByZA=='
    >>> base64.b64decode(encoded)
    'administrator:p@ssw0rd'

Therefore the username sent was `administrator` and the password was `p@ssw0rd`.

### Which hosts appear to be sending broadcast IP packets?

In IPv4, broadcast packets are those sent to a special address which causes them to be received by all hosts on a given subnet. The special address has all its unmasked bits set to `1` [@rfc919], which means ending in a sequence of one or more `255`s when printed in typical 'dotted quad' form.

The Wireshark *Statistics > Conversations* view (shown in Figure \ref{capture1-broadcast}) shows that four hosts are sending packets to `192.168.0.255`, which is the broadcast address for the `192.168.0.0/24` network.

![Wireshark 'Conversations' view for capture1.pcap with broadcast traffic highlighted\label{capture1-broadcast}](capture1-broadcast.png){ width=50% }

The hosts that appear to be sending broadcast IP packets (via UDP) are therefore:

    192.168.0.1
    192.168.0.2
    192.168.0.3
    192.168.0.100

The packets are UDP datagrams on ports 137 and 138 (NetBIOS), meaning we can infer that these hosts are likely to be running Windows.

# References
