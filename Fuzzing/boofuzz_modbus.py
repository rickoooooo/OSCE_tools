#!/usr/bin/env python
from boofuzz import *

"""
The equivalent request to this Modbus RTU example

                 11 03 006B 0003 7687

in Modbus TCP is:

  0001 0000 0006 11 03 006B 0003

0001: Transaction Identifier
0000: Protocol Identifier
0006: Message Length (6 bytes to follow)
11: The Unit Identifier  (17 = 11 hex)
03: The Function Code (read Analog Output Holding Registers)
006B: The Data Address of the first register requested. (40108-40001 = 107 =6B hex)
0003: The total number of registers requested. (read 3 registers 40108 to 40110)
"""

def main():
    session = Session(
        target=Target(
            connection=SocketConnection("192.168.1.7", 27700, proto='tcp')
        ),
        sleep_time=0.1,
    )

    s_initialize(name="ModbusRequest")
    with s_block("Padding-block"):
        s_string('\x42\x42', fuzzable=False, name='Padding')
    with s_block("buf_size-block"):
        s_static('\xFF\xFF', name='buf_size')
    with s_block("recv_len-block"):
        s_size("message-block", fuzzable=False)
    with s_block("header_end-block"):
        s_string('\x44', fuzzable=False, name='header_end')
    with s_block("message_header-block"):
        s_string('\x00\x64', fuzzable=False, name='message_header')
    with s_block("message-block"):
        s_string('AAAA', fuzzable=True, name='message')
    #s_string("\r\n", fuzzable=False, name="CRLF")

    session.connect(s_get("ModbusRequest"))

    session.fuzz()

if __name__ == "__main__":
    main()
