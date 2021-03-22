# encoding: utf-8
from scapy.all import *
import dpkt
import socket
import time
import threading
import sys
import os


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except:
        return False
def getip():
    f = open('aa/demo.pcap', 'rb')  # 要以rb方式打开，用r方式打开会报错
    pcap = dpkt.pcap.Reader(f)
    '''for ts, buf in pcap:                         #备用方案无法正常获取HTTP数据
        print(ts)
        eth = dpkt.ethernet.Ethernet(buf)
        # 这里也是对没有IP段的包过滤掉
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        ip_src = inet_to_str(ip.src)
        ip_dst = inet_to_str(ip.dst)
        print(ip_src + '-->' + ip_dst)
        try:
            request = dpkt.http.Request(ip.data)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            continue
        print('HTTP request: %s\n' % repr(request))'''
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue
        ip = eth.data
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            try:
                request = dpkt.http.Request(tcp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
            print(('IP: %s -> %s ') %(inet_to_str(ip.src), inet_to_str(ip.dst)))#IP地址
            print('HTTP request: %s\n' % repr(request))     #HTTP内容repr(request)
def dealwith():
    print('开始抓包')
    dpkt = sniff(iface="VMware Network Adapter VMnet8", count=10)
    print('抓包成功')
    wrpcap("aa/demo.pcap", dpkt)
    print('所抓的包已经保存')


dealwith()
getip()


