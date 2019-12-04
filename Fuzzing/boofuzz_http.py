#!/usr/bin/env python
from boofuzz import *

def main():
    session = Session(
        target=Target(
            connection=SocketConnection("192.168.1.8", 80, proto='tcp')
        ),
    )

    s_initialize(name="Request")
    with s_block("Request-Line"):
        s_group("Method", ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE'])
        s_delim(" ", fuzzable=False, name='space-1')
        s_string("/browse/1571366277/my%20share/OS2", fuzzable=True, name='Request-URI')
        s_delim(" ", fuzzable=False, name='space-2')
        s_string('HTTP/1.1', fuzzable=True, name='HTTP-Version')
        s_static("\r\n", name="Request-Line-CRLF")
    with s_block("Host-Line"):
        s_string("Host:", fuzzable=False)
        s_delim(" ", fuzzable=False, name='space-3')
        s_string("192.168.1.8", name='Host')
        s_static("\r\n", name="Host-Line-CRLF")
    with s_block("Auth-Line"):
        s_string("Authorization:", fuzzable=False)
        s_delim(" ", fuzzable=False, name='space-4')
        s_string("dGVzdDp0ZXN0", fuzzable=False)
        s_static("\r\n", name="Auth-Line-CRLF")
    with s_block("UA-Line"):
        s_string("User-Agent:", fuzzable=False)
        s_delim(" ", fuzzable=False, name='space-5')
        s_string("Mozilla/5.0", name='User Agent')
        s_static("\r\n", name="UA-Line-CRLF")
    s_static("\r\n", "Request-CRLF")

    session.connect(s_get("Request"))

    session.fuzz()

if __name__ == "__main__":
    main()
