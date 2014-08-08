#!/bin/sh

pcap=$1
if [ -z "$pcap" ]; then
pcap="data/tudou.pcap"
fi
cd .. &&  make && cd example &&  make &&  ./ndpiReader -i $pcap -V2 -d
