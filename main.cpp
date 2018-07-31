#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "header.h"


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}


void printMac_Info (struct ether_h *et_h){
    
    int i;
    printf("---------------------------------------------------------\n"); 
    printf("ETHERNET 패킷\n");
    printf ("dst_mac : ");
    for (i =0 ; i< 6 ; i++ ){
        printf("%02x",et_h->ether_dst_mac[i]);
    	if (i !=5)
                printf(":");
    }
    printf("\n");
    printf ("src_mac : ");
    for (i =0 ; i< 6 ; i++ ){
        printf("%02x",et_h->ether_src_mac[i]);
        if (i !=5)
                printf(":");
    }
    printf("\n");
    printf ("ether_Type : %d(0x%02x)\n",ntohs(et_h->ether_type),ntohs(et_h->ether_type));
    printf("---------------------------------------------------------\n");
}

void printIP_Info (struct ip_hdr *ip_h)
{
    // IP 헤더에서 데이타 정보를 출력한다.
    printf("	---------------------------------------------------------\n");
    printf("	IP 패킷\n");
    printf("	Version     : %d(0x%02x)\n", ip_h->ip_v, ip_h->ip_v);
    printf("	Header Len  : %d(0x%02x)\n", ip_h->ip_hl, ip_h->ip_hl);
    printf("	Ident       : %d(0x%02x)\n", ntohs(ip_h->ip_id), ntohs(ip_h->ip_id));
    printf("	TTL         : %d(0x%02x)\n", ip_h->ip_ttl, ip_h->ip_ttl); 
    printf("	Src Address : %s\n", inet_ntoa(ip_h->ip_src));
    printf("	Dst Address : %s\n", inet_ntoa(ip_h->ip_dst));
    printf("	IP PROTOCOL : %d(0x%02x)\n", ip_h->ip_p, ip_h->ip_p);
    printf("	---------------------------------------------------------\n");
}

void printTCP_Info(struct tcp_hdr *tcp_h) //TCP 20byt info Not Optional Header
{
    printf("		---------------------------------------------------------\n");
    printf("		TCP 패킷\n");
    printf("		Src Port    : %d(0x%04x)\n" , ntohs(tcp_h->th_sport), ntohs(tcp_h->th_sport));
    printf("		Dst Port    : %d(0x%04x)\n" , ntohs(tcp_h->th_dport), ntohs(tcp_h->th_dport));
    printf("		seq Numb    : %d(0x%08x)\n" , ntohs(tcp_h->th_seq), ntohs(tcp_h->th_seq));
    printf("		ack Numb    : %d(0x%08x)\n" , ntohs(tcp_h->th_ack), ntohs(tcp_h->th_ack));
    //printf("		Version     : %02x\n", tcp_h->th_x2);
    printf("		Header Len  : %d(0x%02x)\n", (tcp_h->th_off*4), (tcp_h->th_off*4)); //x4 value is length
    printf("		---------------------------------------------------------\n");
}
//TODO set the UDP
void printUDP_Info(struct tcp_hdr *tcp_h)
{
    printf("		---------------------------------------------------------\n");
    printf("		UDP 패킷\n");
    printf("		Src Port : %d(0x%04x)\n" , ntohs(tcp_h->th_sport), ntohs(tcp_h->th_sport));
    printf("		Dst Port : %d(0x%04x)\n" , ntohs(tcp_h->th_dport), ntohs(tcp_h->th_dport));      
    printf("		---------------------------------------------------------\n");
}

int main(int argc, char* argv[]) {
  int i;
  struct pcap_pkthdr* header;
  struct ether_h * et_h;
  struct ip_hdr *ip_h;
  struct tcp_hdr *tcp_h;

  unsigned short eth_type;
  struct iphdr *iph; 
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    

    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    et_h = (struct ether_h *)packet;

    //get ip header info
    
    //ETHERTYPE_IP 0x800
    if ( ntohs(et_h->ether_type) == ETHERTYPE_IP)
    {
        packet += sizeof(struct ether_header);
        ip_h = (struct ip_hdr *)packet;
        printMac_Info(et_h);
        printIP_Info(ip_h);
        //0x05 05 TCP info 
        if (ip_h->ip_p == IPPROTO_TCP)
        {
            packet += sizeof(struct ip_hdr);
            tcp_h = (struct tcp_hdr*)packet;
	    printTCP_Info(tcp_h);
	    packet += tcp_h->th_off*4;
	    printf("		data\n");
	    for (i=0; i< 16 ; i++ ){
                  printf("%02x",packet[i]);
	    }
	    printf("		\n");	
		
        }
        //0x11 17 UDP info
        else if (ip_h->ip_p == IPPROTO_UDP)
        {
            packet += sizeof(struct ip_hdr);
            tcp_h = (struct tcp_hdr*)packet;
            printUDP_Info(tcp_h);
        }
    }

  }
  pcap_close(handle);
  return 0;
}
