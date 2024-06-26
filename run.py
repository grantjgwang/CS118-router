#!/usr/bin/env python3

"""
Start up a Simple topology for CS118
"""

import mininet.net
import mininet.node

from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.util import quietRun
from mininet.moduledeps import pathCheck

from sys import exit
import os.path
from subprocess import Popen, STDOUT, PIPE, check_call

IPBASE = '10.3.0.0/16'
ROOTIP = '10.3.0.100/16'
IPCONFIG_FILE = './IP_CONFIG'
IP_SETTING={}

class TwoServerClientAndRouterTopology(Topo):
    "Topology with 2 servers and 1 client connected with a switch/router"

    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )
        server1 = self.addHost( 'server1' )
        server2 = self.addHost( 'server2' )
        router = self.addSwitch( 'sw0' )
        client = self.addHost('client', inNamespace=False)
        for h in server1, server2, client:
            self.addLink( h, router )

def set_default_route(host):
    info('*** setting default gateway of host %s\n' % host.name)
    if(host.name == 'server1'):
        routerip = IP_SETTING['sw0-eth1']
    elif(host.name == 'server2'):
        routerip = IP_SETTING['sw0-eth2']
    elif(host.name == 'client'):
        routerip = IP_SETTING['sw0-eth3']
    print(host.name, routerip)
    host.cmd('route add %s/32 dev %s-eth0' % (routerip, host.name))
    host.cmd('route add default gw %s dev %s-eth0' % (routerip, host.name))
    ips = IP_SETTING[host.name].split(".")
    host.cmd('route del -net %s.0.0.0/8 dev %s-eth0' % (ips[0], host.name))

def set_default_route_client(host):
    info('*** setting default gateway of client %s\n' % host.name)
    routerip = IP_SETTING['sw0-eth3']
    print(host.name, routerip)
    for eth in ['sw0-eth1', 'sw0-eth2', 'sw0-eth3']:
        swip = IP_SETTING[eth]
        pref = ".".join(swip.split(".")[:-1]) + ".0"
        print(pref)
        check_call('route add -net %s/24 gw 172.32.10.1 dev client-eth0' % (pref), shell = True)

def get_ip_setting():
    try:
        with open(IPCONFIG_FILE, 'r') as f:
            for line in f:
                if( len(line.split()) == 0):
                  break
                name, ip = line.split()
                print(name, ip)
                IP_SETTING[name] = ip
            info( '*** Successfully loaded ip settings for hosts\n %s\n' % IP_SETTING)
    except EnvironmentError:
        exit("Couldn't load config file for ip addresses, check whether %s exists" % IPCONFIG_FILE)

def main():
    "Create a simple network"
    get_ip_setting()
    topo = TwoServerClientAndRouterTopology()
    info( '*** Creating network\n' )
    net = mininet.net.Mininet(topo=topo, controller=mininet.node.RemoteController, ipBase=IPBASE )
    net.start()
    server1, server2, client, router = net.get( 'server1', 'server2', 'client', 'sw0')
    s1intf = server1.defaultIntf()
    s1intf.setIP('%s/8' % IP_SETTING['server1'])
    s2intf = server2.defaultIntf()
    s2intf.setIP('%s/8' % IP_SETTING['server2'])
    clintf = client.defaultIntf()
    clintf.setIP('%s/8' % IP_SETTING['client'])

    for host in server1, server2:
        set_default_route(host)
    set_default_route_client(client)
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
