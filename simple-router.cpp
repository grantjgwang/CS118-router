/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>
#include <iterator>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  std::cerr << "===========" << std::endl << "received packet: " << std::endl;
  print_hdrs(packet);

  // check if type if IPv4
  ethernet_hdr* ethernet_header = (ethernet_hdr*)packet.data();
  if(ethernet_header->ether_type != htons(ethertype_ip)){
    std::cerr << "Ethernet frame type not IPv4, ignore" << std::endl;
    return;
  }

  // check for dest aaddress, ignore if not this router or broadcast 
  uint8_t* dest_mac = ethernet_header->ether_dhost;
  const uint8_t* curr_mac = iface->addr.data();
  bool equal_curr_mac = true;
  bool equal_bd_mac = true;
  for(int i = 0; i < ETHER_ADDR_LEN; i++) {
    if(dest_mac[i] != curr_mac[i]) {
      equal_curr_mac = false;
    }
    if(dest_mac[i] != BroadcastEtherAddr[i]) {
      equal_bd_mac = false;
    }
  }
  if(!equal_bd_mac && !equal_curr_mac) {
    std::cerr << "Ethernet frame not destined to current MAC address or broadcast address, ignore" << std::endl;
    return;
  }

  // get IPv4 header and check min length and checksum
  ip_hdr* ipv4_header = (ip_hdr*)(packet.data() + sizeof(ethernet_hdr));
  if(ipv4_header->ip_hl < 5) {
    std::cerr << "Invalid IPv4 header length, discard" << std::endl;
    return;
  }
  uint16_t og_ipv4_checksum = ipv4_header->ip_sum;
  ipv4_header->ip_sum = 0;
  uint16_t ipv4_checksum = cksum(ipv4_header, sizeof(ip_hdr));
  if(og_ipv4_checksum != ipv4_checksum) {
    std::cerr << "Invalid IP chechsun, discard" << std::endl;
    return;
  }

  // check dest ip
  const Interface* match_interface = findIfaceByIp(ipv4_header->ip_dst);
  ipv4_header->ip_ttl -= 1;
  if(match_interface != nullptr) {
    // destined to the router 
    if(ipv4_header->ip_p == ip_protocol_icmp) {
      // get the ICMP header 
      icmp_hdr* icmp_header = (icmp_hdr*)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
      if(icmp_header->icmp_type != 8) {
        std::cerr << "Not ICMP Echo message, discaard" << std::endl;
        return;
      }

      // checksum
      uint16_t og_icmp_checksum = icmp_header->icmp_sum;
      icmp_header->icmp_sum = 0;
      uint16_t icmp_checksum = cksum(icmp_header, packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr));
      if(og_icmp_checksum != icmp_checksum) {
        std::cerr << "Invalid ICMP checksum, discard" << std::endl; 
        return;
      }
      // reply with echo reply message
      Buffer reply_packet(packet);
      RoutingTableEntry reply_hop;
      try {
        reply_hop = m_routingTable.lookup(ipv4_header->ip_src);
      }
      catch(std::runtime_error& err) {
        std::cerr << "Routing table runtime error(Echo Reply)" << std::endl;
        return;
      }
      auto arp_entry = m_arp.lookup(reply_hop.gw);
      ethernet_hdr* reply_ethernet_header = (ethernet_hdr*)reply_packet.data();
      ip_hdr* reply_ipv4_header = (ip_hdr*)(reply_packet.data() + sizeof(ethernet_hdr));
      icmp_hdr* reply_icmp_header = (icmp_hdr*)(reply_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
      uint8_t t1[ETHER_ADDR_LEN];
      for(int i = 0; i < ETHER_ADDR_LEN; i++) {
        t1[i] = reply_ethernet_header->ether_shost[i];
        reply_ethernet_header->ether_shost[i] = reply_ethernet_header->ether_dhost[i];
        reply_ethernet_header->ether_dhost[i] = t1[i];
      }
      uint32_t t2 = reply_ipv4_header->ip_src;
      reply_ipv4_header->ip_src = reply_ipv4_header->ip_dst;
      reply_ipv4_header->ip_dst = t2;
      reply_ipv4_header->ip_ttl = 64;
      reply_ipv4_header->ip_sum = 0;
      reply_ipv4_header->ip_sum = cksum(reply_ipv4_header, sizeof(ip_hdr));
      reply_icmp_header->icmp_type = 0;
      reply_icmp_header->icmp_sum = 0;
      reply_icmp_header->icmp_sum = cksum(reply_icmp_header, packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr));
      if(!arp_entry) {
        m_arp.queueRequest(reply_hop.gw, reply_packet, reply_hop.ifName);
      }
      else{
        sendPacket(reply_packet, reply_hop.ifName);
        
      }
      std::cerr << "Reply packet: " << std:endl;
      print_hdrs(reply_packet);
    }
    else {
      std::cerr << "Not ICMP, discard" << std::endl;
      return;
    }
  }
  else {
    // forward
    RoutingTableEntry next_hop;
    try {
      next_hop = m_routingTable.lookup(ipv4_header->ip_dst);
    }
    catch(std::runtime_error& err) {
      std::cerr << "Routing table runtime error" << std::endl;
      return;
    }
    const Interface* out_interface = findIfaceByName(next_hop.ifName);
    auto arp_entry = m_arp.lookup(next_hop.gw);
    if(!arp_entry) {
      m_arp.queueRequest(next_hop.gw, packet, next_hop.ifName);
    }
    else{
      memcpy(ethernet_header->ether_shost, &out_interface->addr, sizeof(ethernet_header->ether_shost));
      memcpy(ethernet_header->ether_dhost, &arp_entry->mac, sizeof(ethernet_header->ether_dhost));
      ipv4_header->ip_sum = 0;
      ipv4_header->ip_sum = cksum(ipv4_header, sizeof(ip_hdr));
      sendPacket(packet, next_hop.ifName);
    }
    std:: cerr << "Forward packet: " << std:: endl;
    print_hdrs(packet);
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
