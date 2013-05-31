/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

int isAddrEqual(const uint8_t *addr1, const uint8_t *addr2)
{
  int i;
  for(i = 0; i != ETHER_ADDR_LEN; i++)
  {
    if (*addr1 != *addr2)
      return 0;
    ++addr1;
    ++addr2;
  }
  return 1;
}
/*to be implement*/

uint8_t* newArpPacket(unsigned short op, unsigned char *sha, uint32_t sip, unsigned char *tha, uint32_t tip)
{
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t* packet = malloc(len);
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*) packet;
  sr_arp_hdr_t* a_hdr = (sr_arp_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t));
  memcpy(e_hdr->ether_dhost, tha, ETHER_ADDR_LEN);
  memcpy(e_hdr->ether_shost, sha, ETHER_ADDR_LEN);
  e_hdr->ether_type = htons(ethertype_arp);

  a_hdr->ar_hrd = htons(arp_hrd_ethernet);
  a_hdr->ar_pro = htons(ethertype_ip);
  a_hdr->ar_hln = ETHER_ADDR_LEN;
  a_hdr->ar_pln = 4;
  a_hdr->ar_op = htons(op);
  memcpy(a_hdr->ar_sha, sha, ETHER_ADDR_LEN);
  a_hdr->ar_sip = sip;
  memcpy(a_hdr->ar_tha, tha, ETHER_ADDR_LEN);
  a_hdr->ar_tip = tip;

  return packet;
}

void handleArpPacket(struct sr_instance* sr, sr_arp_hdr_t* arp_hdr, 
                        unsigned int len, struct sr_if *iface)
{
  if (arp_hdr->ar_hrd != htons(arp_hrd_ethernet) || arp_hdr->ar_pro != htons(ethertype_ip))
  {
    fprintf(stderr, "Hardware type or Protocol type error.\n");
    return;
  }

  if(arp_hdr->ar_op == htons(arp_op_request))
  {
    if(iface->ip == arp_hdr->ar_tip)
    {
        unsigned int reply_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
        print_addr_ip_int(iface->ip);
        uint8_t* reply_pkt = newArpPacket(arp_op_reply, iface->addr, iface->ip, arp_hdr->ar_sha, arp_hdr->ar_sip);
        sr_send_packet(sr,reply_pkt,reply_len, iface->name);
        free(reply_pkt);
    }
    
  }
  else if(arp_hdr->ar_op == htons(arp_op_reply))
  {
    if(iface->ip == arp_hdr->ar_tip)
    {
      struct sr_arpreq* req_pointer = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
      if(req_pointer == NULL)
        printf("Received arp reply, no other request\n");
      else
      {
        while(req_pointer->packets != NULL)
        {
        /*send all packet waiting on this reply 

          struct sr_packet* waiting_pkt = req_pointer->packets;
          memcpy(((sr_ethernet_hdr_t*)waiting_pkt->buf))->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
          sr_send_packet(sr, waiting_pkt->buf, waiting_pkt->len, waiting_pkt->iface);
          req_pointer->packets = req_pointer->packets->next;
          */
        }
      }
    }
  }
  else 
  {
        fprintf(stderr, "Wrong operation.");

  }
}
void handleIpPacket(struct sr_instance* sr, uint8_t* packet, 
                        unsigned int len, struct sr_if *iface)
{
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t));
  if (ip_hdr->ip_sum != cksum(ip_hdr, len))
  {
    fprintf(stderr, "Checksum doesn't match, but we keep going.\n");

  }

  struct sr_rt* rt = sr->routing_table;
  uint32_t gw;
  if(/*des ip is router*/ 0)
  {
    if(ip_hdr->ip_p == ip_protocol_icmp)
    {
        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    }
    else
    {

    }
  }
  else/*des ip is not router*/
  {
    for(;rt->next != NULL;rt->next)
    {

      if(ip_hdr->ip_dst == rt->dest.s_addr)
        gw = rt->gw.s_addr;
      break;
    }
    if(!gw)
    {
      fprintf(stderr, "routing entry is not found\n");
      return;
    }

    ip_hdr->ip_ttl -= 1;
    if(ip_hdr->ip_ttl == 0)
    {
      /*ICMP time exceed*/
      fprintf(stderr, "ICMP time exceed.\n");
      sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      icmp_hdr->icmp_type = 0xB;
      unsigned char* sha = e_hdr->ether_shost;
      memcpy(e_hdr->ether_shost, e_hdr->ether_dhost, ETHER_ADDR_LEN);
      memcpy(e_hdr->ether_dhost, sha, ETHER_ADDR_LEN);
      for(;iface!=NULL;iface=iface->next)
      {
        if(iface->ip == ip_hdr->ip_dst)
          sr_send_packet(sr,packet,len, iface->name);
        return;
      }
    }

    /*routhing entry found*/
    struct sr_arpentry* arp_entry;
    uint32_t next_hop_ip = ntohl(gw);
    arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
    memcpy(e_hdr->ether_shost, sr_get_interface(sr, rt->interface)->addr, ETHER_ADDR_LEN);
    fprintf(stderr, "prepare to send arp req\n");
    if(arp_entry != NULL)
    {
      memcpy(e_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, rt->interface);
      free(arp_entry);
      fprintf(stderr, "mac in table, send ip\n");

    }
    else
    {
    uint8_t bc[ETHER_ADDR_LEN]  = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    unsigned int req_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
    uint8_t* arp_req = newArpPacket(arp_op_request, iface->addr, iface->ip, bc, gw);
    sr_send_packet(sr, arp_req, req_len, iface->name);
    fprintf(stderr, "mac not in table, send arp req\n");

    }
  }
}

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  print_hdrs(packet, len);
  sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) packet;
  if(len < sizeof(sr_ethernet_hdr_t)) 
  {
    fprintf(stderr, "Dropped, too short as ethernet frame\n");
    return;
  }

  struct sr_if* iface = sr_get_interface(sr, interface);
  if(ethertype(packet) == ethertype_arp) 
  {
        handleArpPacket(sr, (sr_arp_hdr_t* )(packet+sizeof(sr_ethernet_hdr_t)), 
                        len-sizeof(sr_ethernet_hdr_t), iface);
  }
  else if(ethertype(packet) == ethertype_ip)
  {
    if(isAddrEqual(ether_hdr->ether_dhost, iface->addr))
      handleIpPacket(sr, packet, len, iface);
    else
      fprintf(stderr,"Not for this interface.\n");
  }
  else
    fprintf(stderr, "Dropped, wrong entertype.\n");
}/* end sr_ForwardPacket */

