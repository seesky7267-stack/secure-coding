#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>


/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) // Ethernet Frame인지, IP Packet인지, TCP Segement인지 분류하는 함수
{
  // TCP protocol만을 대상으로 하므로 EthernetType이 0x0800이고 iph_protocl이 IPPROTO_TCP인 것을 조건문으로 함
  struct ethheader * ether = (struct ethheader *) packet; 
  struct ipheader * ip = (struct ipheader *) (packet + sizeof(struct ethheader)); // ipheader의 시작점
  if ((ntohs(ether->ether_type) == 0x0800) && ((ip->iph_protocol) == IPPROTO_TCP))
  { 
    printf(" TCP protocol detected!\n=================\n");
    printf("Source MAC Address : ");
    for(int i=0;i<5;i++)
      printf("%02x:", *((ether->ether_shost)+i));   // Source MAC 정보를 출력
    printf("%02x\n", *((ether->ether_shost)+5));
    printf("Destination MAC Address : ");
    for(int i=0;i<5;i++)
      printf("%02x:", *((ether->ether_dhost)+i));    // Destination MAC 정보를 출력
    printf("%02x\n=================\n", *((ether->ether_dhost)+5)); 
    printf("Source IP Address : %s\n", inet_ntoa(ip->iph_sourceip));   // Source IP 정보를 출력
    printf("Destination IP Address: %s\n=================\n", inet_ntoa(ip->iph_destip));    // Destination IP 정보를 출력
    struct tcpheader * tcp = (struct tcpheader *) (packet + sizeof(struct ethheader) + (ip->iph_ihl) * 4); // tcpheader의 시작점
    printf("Source Port Address : %d\n", ntohs((tcp->tcp_sport)));   // Source port 정보를 출력
    printf("Destination Port Address: %d\n=================\n", ntohs((tcp->tcp_dport)));    // Destination port 정보를 출력
    u_char TCP_header_length = ((tcp->tcp_offx2 & 0xf0) >> 4) * 4; // TCP Header 길이는 상위 4비트에 들어있으므로, 또 4bye 단위로 표시하므로
    u_char *HTTP_message = (u_char *)tcp + TCP_header_length; // TCP 시작점 + TCP Header 길이 = TCP payload 시작점
    printf("HTTP Message : ");
    for(int i = 0; i< (int)((header->caplen) - (HTTP_message - packet)); i++)
    	printf("%c", HTTP_message[i]); // HTTP Message
    printf("\n=================\n");
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;
  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }
  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);
  pcap_close(handle);   //Close the handle
  return 0;
}


