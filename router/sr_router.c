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
  unsigned int = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t* packet = malloc(len);
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*) packet;
  sr_arp_hdr_t* a_hdr = (sr_arp_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t));
  memcpy(e_hdr->ether_dhost, tha, ETHER_ADDR_LEN);
  memcpy(e_hdr->ether_shost, sha, ETHER_ADDR_LEN);
  e_hdr->ether_type = htons(ethertype_arp);

  a_hdr->ar_hrd = htons(arp_hrd_ethernet);
  a_hdr->ar_pro = htons(ethertype_ip);
  a_hdr->ar_hln = ETHER_ADDR_LEN;
  a_hdr->ar_pln = IP_ADDR_LEN;
  a_hdr->ar_op = htons(op);
  memcpy(a_hdr->sha, sha, ETHER_ADDR_LEN);
  a_hdr->ar_sip = sip;
  memcpy(a_hdr->tha, tha, ETHER_ADDR_LEN);
  a_hdr->tip = tip;

  return packet;
}

void handleArpPacket(struct sr_instance* sr, sr_arp_hdr_t* arp_hdr, 
                        unsigned int len, struct sr_if *iface, int is_broadcast)
{
  if (arp_hdr->ar_hrd != arp_hrd_ethernet || arp_hdr->ar_pro != ethertype_ip)
  {
    fprintf(stderr, "Hardware type or Protocol type error.")
    return;
  }

  if(arp_hdr->op == 1)
  {
    unsigned int reply_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
    uint8_t* reply_pkt = newArpPacket(arp_op_reply, iface->addr, iface->ip, arp_hdr->ar_sha, arp_hdr->ar_sip);
    sr_send_packet(sr,reply_pkt,reply_len, iface->name);
    free(reply_pkt);
  }
  else
  {
    if(is_broadcast)
    {
        fprintf(stderr, "Wrong operation.")
        return;
    }
  }
}
void handleIpPacket(struct sr_instance* sr, sr_ip_hdr_t* ip_hdr, 
                        unsigned int len, struct sr_if *iface)
{}

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
  if(len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "Dropped, too short as ethernet frame\n");
    return;
  }

  struct sr_if* iface = sr_get_interface(sr, interface);
  if(ethertype(packet) == ethertype_arp) 
  {
    uint8_t bc[ETHER_ADDR_LEN]  = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    int is_broadcast = isAddrEqual(ether_hdr->ether_dhost,bc);
    if(isAddrEqual(ether_hdr->ether_dhost,iface->addr) || is_broadcast) 
    {
        handleArpPacket(sr, (sr_arp_hdr_t* )(packet+sizeof(sr_ethernet_hdr_t)), 
                        len-sizeof(sr_ethernet_hdr_t), iface, is_broadcast);
    }
    else
    {
      fprintf(stderr, "Dropped, distance address is not recognized");
      return;
    }
  }
  else if(ethertype(packet) == ethertype_ip)
  {
    if(isAddrEqual(ether_hdr->ether_dhost, iface->addr))
      handleIpPacket(sr, (sr_ip_hdr_t* )(packet+sizeof(sr_ethernet_hdr_t)),
                      len-sizeof(sr_ethernet_hdr_t), iface);
    else
      return;
  }
  else
    fprintf(stderr, "Dropped, wrong entertype");
}/* end sr_ForwardPacket */

