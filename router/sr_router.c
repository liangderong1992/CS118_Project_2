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

int isRouterIp(struct sr_instance* sr,uint32_t dstip)
{
	struct sr_if* interface_p = sr->if_list;
	while(interface_p!=NULL)
	{
		if(interface_p->ip == dstip)
			return 1;
		interface_p = interface_p->next;
	}
	return 0;
}

uint32_t get_gw(struct sr_instance* sr,char * name)
{
	struct sr_rt* rt_p = sr->routing_table;
	for(;rt_p!=NULL;rt_p = rt_p->next)
	{
		int i;
		for(i=0;i<sr_IFACE_NAMELEN;i++)
		{
			if((*(name+i)) != (*((rt_p->interface)+i)))
				break;
		}
		if(i == sr_IFACE_NAMELEN)
			return rt_p->gw.s_addr;
	}
	return 0;
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
		print_hdrs(reply_pkt,reply_len);
        free(reply_pkt);
    }
    
  }
  else if(arp_hdr->ar_op == htons(arp_op_reply))
  {
    if(iface->ip == arp_hdr->ar_tip)
    {
      struct sr_arpreq* req_pointer = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
	  fprintf(stderr,"$$$$$$ between cache print\n");
	sr_arpcache_dump(&sr->cache);
		fprintf(stderr,"$$$$$$ between cache print\n");
      if(req_pointer == NULL)
        printf("Received arp reply, no other request\n");
      else
      {
        while(req_pointer->packets != NULL)
        {
        /*send all packet waiting on this reply */

          struct sr_packet* waiting_pkt = req_pointer->packets;
          memcpy(((sr_ethernet_hdr_t*)waiting_pkt->buf)->ether_shost, arp_hdr->ar_tha, ETHER_ADDR_LEN);

          memcpy(((sr_ethernet_hdr_t*)waiting_pkt->buf)->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
          sr_send_packet(sr, waiting_pkt->buf, waiting_pkt->len, waiting_pkt->iface);
          req_pointer->packets = req_pointer->packets->next;
          
        }
        sr_arpreq_destroy(&(sr->cache),req_pointer);
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
  uint16_t copysum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  if (copysum != cksum((uint8_t*)(packet+sizeof(sr_ethernet_hdr_t)),20))
  {
    fprintf(stderr, "Checksum doesn't match, but we keep going.\n");
  }
	fprintf(stderr, "Checksum matches\n");


fprintf(stderr,"before isrouterip\n");

  if(isRouterIp(sr,ip_hdr->ip_dst))
  {
	fprintf(stderr,"packet whose ip is router's ip\n");
    if(ip_hdr->ip_p == ip_protocol_icmp)
    {
      /*sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));*/
	  /*ToDo: get the icmp type and opcode and do whatever....*/
		uint8_t * erICMP = newERICMPPacket(packet,len);
		fprintf(stderr,"*** -> here is the sending out echo reply(only for debuging) when receiving icmp\n");
		print_hdrs(erICMP,102);
		sr_send_packet(sr,erICMP,len,iface->name);
		return;
    }
    else /*here it is an IP packet, send an HU ICMP back*/
    {
		fprintf(stderr,"here it is an IP packet, send an PU ICMP back\n");
		uint8_t * puICMP = newPUICMPPacket(packet,e_hdr->ether_dhost,iface->ip,e_hdr->ether_shost,ip_hdr->ip_src);
		/*ToDo: we have to use port unreachable ICMP packet*/
		fprintf(stderr,"*** -> here is the sending out puicmp when receiving ip\n");
		print_hdrs(puICMP,102);
		if(sr_send_packet(sr,puICMP,sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t),iface->name)==-1)
			fprintf(stderr,"Error sending puICMP when IP is routerIP\n");
		return;
    }
  }
  else
  {
	fprintf(stderr,"before match\n");
	struct sr_if* interface_p = matchPrefix(sr,ip_hdr->ip_dst);
	if(interface_p==NULL)
	{
		/*ToDo: send the client back a NU icmp */
		fprintf(stderr,"routing match not found\n");
		return;
	}
	
	fprintf(stderr,"after match\n");
    ip_hdr->ip_ttl -= 1;
    if(ip_hdr->ip_ttl == 0)
    {
      /*ICMP time exceed*/
      fprintf(stderr, "ICMP time exceed.\n");
	  return;
	  /* ToDo: send back a ICMP time exceed packet,similiar to the t3_icmp */

      /*sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      icmp_hdr->icmp_type = 0xB;
      unsigned char* sha = e_hdr->ether_shost;
      memcpy(e_hdr->ether_shost, e_hdr->ether_dhost, ETHER_ADDR_LEN);
      memcpy(e_hdr->ether_dhost, sha, ETHER_ADDR_LEN);
      for(;iface!=NULL;iface=iface->next)
      {
        if(iface->ip == ip_hdr->ip_dst)
          sr_send_packet(sr,packet,len, iface->name);
        return;
      }*/
    }
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum(ip_hdr,20);

/*routhing entry found*/
    struct sr_arpentry* arp_entry;
    uint32_t receiverifip = ntohl(iface->ip);
	fprintf(stderr,"before lookup\n");
    arp_entry = sr_arpcache_lookup(&sr->cache, receiverifip);
	fprintf(stderr,"after lookup\n");

	/*int i;
	for(i=0;i<ETHER_ADDR_LEN;i++)
	{
		e_hdr->ether_dhost[i] = (uint8_t)interface_p->addr[i];
	}*/
    fprintf(stderr, "prepare to send arp req\n");
    

    if(arp_entry != NULL)
    {
      memcpy(e_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
	  memcpy(e_hdr->ether_shost, interface_p->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, interface_p->name);
      free(arp_entry);
      fprintf(stderr, "mac in table, send ip\n");
    }
    else
    {
	fprintf(stderr, "mac not in table, want to send arp req\n");
    uint8_t bc[ETHER_ADDR_LEN]  = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	fprintf(stderr,"before queuereq\n");
    struct sr_arpreq* a_req = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet, len, interface_p->name);
    fprintf(stderr,"after queuereq\n");
    handle_arpreq(sr, a_req);

    /*unsigned int req_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
	uint32_t next_hop_ip = get_gw(sr,interface_p->name);
	if(next_hop_ip == 0)
		fprintf(stderr,"cannot fond gw in the rt\n");
    uint8_t* arp_req = newArpPacket(arp_op_request, interface_p->addr, interface_p->ip, bc, next_hop_ip);
    fprintf(stderr,"*** -> sending the arp req below\n");
    sr_send_packet(sr, arp_req, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface_p->name);
    uint8_t* huicmp = newHUICMPPacket(packet, iface->addr, iface->ip, interface_p->addr, interface_p->ip);
    print_hdrs(arp_req, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));*/

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
    {
	  fprintf(stderr,"entering handleippacket\n");
      handleIpPacket(sr, packet, len, iface);
    }
    else
      fprintf(stderr,"Not for this interface.\n");
  }
  else
    fprintf(stderr, "Dropped, wrong entertype.\n");
}/* end sr_ForwardPacket */

