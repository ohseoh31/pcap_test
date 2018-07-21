
struct ether_h
{
  unsigned char ether_dst_mac[6];  /*dst_mac 6byte*/
  unsigned char ether_src_mac[6];  /*src_mac 6byte*/  
  unsigned short ether_type; //2byte
};


struct ip_hdr
{
    unsigned int ip_hl:4;   /* header length */
    unsigned int ip_v:4;    /* version */
    u_int8_t ip_tos;        /* type of service */
    u_short ip_len;         /* total length */
    u_short ip_id;          /* identification */
    u_short ip_off;         /* fragment offset field */
    u_int8_t ip_ttl;        /* time to live */
    u_int8_t ip_p;          /* protocol */
    u_short ip_sum;         /* checksum */
    struct in_addr ip_src;
    struct in_addr ip_dst;
 };


struct tcp_hdr
{
    u_int16_t th_sport;     /* source port */
    u_int16_t th_dport;     /* destination port */
    tcp_seq th_seq;         /* sequence number */
    tcp_seq th_ack;         /* acknowledgement number */
    u_int8_t th_x2:4;       /* (unused) */
    u_int8_t th_off:4;      /* data offset */
    u_int8_t th_flags;      
    u_int16_t th_win;       /* window */
    u_int16_t th_check;       /* checksum */
    u_int16_t th_urp;       /* urgent pointer */
};

struct dns_hdr
{
    u_int16_t th_sport;
    u_int16_t th_dport;
};
