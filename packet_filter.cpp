#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>

#include <pcap.h>
#define TELNET 23
#define HTTP 80
#define SERVER 0
#define CLIENT 1
using namespace std;

/* We've included the UDP header struct for your ease of customization.
 * For your protocol, you might want to look at netinet/tcp.h for hints
 * on how to deal with single bits or fields that are smaller than a byte
 * in length.
 *
 * Per RFC 768, September, 1981.
 */
struct UDP_hdr {
    u_short uh_sport;               /* source port */
    u_short uh_dport;               /* destination port */
    u_short uh_ulen;                /* datagram length */
    u_short uh_sum;                 /* datagram checksum */
};

struct TCP_hdr {
    unsigned short int th_sport;
    unsigned short int th_dport;
    unsigned int       th_seqnum;
    unsigned int       th_acknum;
    unsigned char      th_reserved:4, th_offset:4;
    // unsigned char tcph_flags;
    unsigned int
        tcp_res1:4,       /*little-endian*/
        th_hlen:4,      /*length of tcp header in 32-bit words*/
        th_fin:1,       /*Finish flag "fin"*/
        th_syn:1,       /*Synchronize sequence numbers to start a connection*/
        th_rst:1,       /*Reset flag */
        th_psh:1,       /*Push, sends data to the application*/
        th_ack:1,       /*acknowledge*/
        th_urg:1,       /*urgent pointer*/
        th_res2:2;
    unsigned short int th_win;
    unsigned short int th_chksum;
};



/* Some helper functions, which we define at the end of this file. */

/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);

/* Report a problem with dumping the packet with the given timestamp. */
void problem_pkt(struct timeval ts, const char *reason);

/* Report the specific problem of a packet being too short. */
void too_short(struct timeval ts, const char *truncated_hdr);

bool isValidHTTPReqMethod(unsigned char *cptr)
{
	return true;	
}

bool isValidHTTPResponse(unsigned char *cptr)
{
	return true;
}

void print_http_session(bool clientflag, unsigned char *cptr, int capture_len)
{
    if (capture_len < 10)
        return;
    //cout<<"Len"<<capture_len<<' ';
	if(clientflag)
	{
		if(cptr[0] != 'G' || cptr[1] != 'E' || cptr[2] != 'T')
			return;
	} else {
		if(cptr[0] != 'H' || cptr[1] != 'T' || cptr[2] != 'T' || cptr[3] != 'P')
			return;
	}

    for(int i=0;i<capture_len;i++)
    {
		if(cptr[i]==13 && cptr[i+1]==10 && cptr[i+2]==13 && cptr[i+3]==10)
		{
			cout<<"\n";
			return;
		}
        if(cptr[i] >= 32 && cptr[i] < 127 || cptr[i] ==10 || cptr[i] ==13)
            printf("%c", cptr[i]);
        else
        {
            switch(cptr[i])
            {
				case 10:
					cout<<"\n";
                default:;
                    printf("%u", cptr[i]);
            }
        }
    }
}

void print_telnet_session(bool clientflag, unsigned char *cptr, int capture_len)
{
    for(int i=0;i<capture_len;i++)
    {
        if(cptr[i] >= 32 && cptr[i] < 127 )
            printf("%c", cptr[i]);
        else
        {
            switch(cptr[i])
            {
				case 10:
					cout<<"\n";
                default:;
                    printf("%u", cptr[i]);
            }
        }
    }
}

void print_ftp_session(bool clientflag, unsigned char *cptr, int capture_len)
{
    for(int i=0;i<capture_len;i++)
    {
        if(cptr[i] >= 32 && cptr[i] < 127)
            printf("%c", cptr[i]);
        else
        {
            switch(cptr[i])
            {
				case 10:
					cout<<"\n";
                default:;
                    printf("%u", cptr[i]);
            }
        }
    }
}

void process_tcp_packet(const unsigned char *packet, struct timeval ts,
        unsigned int capture_len)
{
    struct ip *ip;
    int i;
    struct TCP_hdr *tcp;
    unsigned int IP_header_length;
    unsigned int TCP_hdr_len = sizeof(struct TCP_hdr);
    unsigned char *cptr;

    /* For simplicity, we assume Ethernet encapsulation. */

    if (capture_len < sizeof(struct ether_header))
    {
        /* We didn't even capture a full Ethernet header, so we
         * can't analyze this any further.
         */
        too_short(ts, "Ethernet header");
        return;
    }

    /* Skip over the Ethernet header. */
    packet += sizeof(struct ether_header);
    capture_len -= sizeof(struct ether_header);

    if (capture_len < sizeof(struct ip))
    { /* Didn't capture a full IP header */
        too_short(ts, "IP header");
        return;
    }

    ip = (struct ip*) packet;
    IP_header_length = ip->ip_hl * 4;       /* ip_hl is in 4-byte words */

    if (capture_len < IP_header_length)
    { /* didn't capture the full IP header including options */
        too_short(ts, "IP header with options");
        return;
    }

    if (ip->ip_p != IPPROTO_TCP)
    {
        problem_pkt(ts, "non-TCP packet");
        return;
    }

    /* Skip over the IP header to get to the UDP header.*/
    packet += IP_header_length;
    capture_len -= IP_header_length;

    if (capture_len < sizeof(struct TCP_hdr))
    {
        too_short(ts, "TCP header");
        return;
    }

    tcp = (struct TCP_hdr*) packet;
    cptr = (unsigned char *)packet;
    cptr += sizeof(struct TCP_hdr);
    capture_len -= sizeof(struct TCP_hdr);

	int srcport = ntohs(tcp->th_sport);
	int dstport = ntohs(tcp->th_dport);

	switch(srcport)
	{
		case 80:
			print_http_session(SERVER, cptr, capture_len);
			break;
		case 23:
			print_telnet_session(SERVER, cptr, capture_len);
			break;
		case 21:
			print_ftp_session(SERVER, cptr, capture_len);
			break;
		default:
			break;
	}

	switch(dstport)
	{
		case 80:
			print_http_session(CLIENT, cptr, capture_len);
			break;
		case 23:
			print_telnet_session(CLIENT, cptr, capture_len);
			break;
		case 21:
			print_ftp_session(CLIENT, cptr, capture_len);
			break;
		default:
			break;
	}
}


/* dump_UDP_packet()
 *
 * This routine parses a packet, expecting Ethernet, IP, and UDP headers.
 * It extracts the UDP source and destination port numbers along with the UDP
 * packet length by casting structs over a pointer that we move through
 * the packet.  We can do this sort of casting safely because libpcap
 * guarantees that the pointer will be aligned.
 *
 * The "ts" argument is the timestamp associated with the packet.
 *
 * Note that "capture_len" is the length of the packet *as captured by the
 * tracing program*, and thus might be less than the full length of the
 * packet.  However, the packet pointer only holds that much data, so
 * we have to be careful not to read beyond it.
 */
void dump_UDP_packet(const unsigned char *packet, struct timeval ts,
        unsigned int capture_len)
{
    struct ip *ip;
    struct UDP_hdr *udp;
    unsigned int IP_header_length;

    /* For simplicity, we assume Ethernet encapsulation. */

    if (capture_len < sizeof(struct ether_header))
    {
        /* We didn't even capture a full Ethernet header, so we
         * can't analyze this any further.
         */
        too_short(ts, "Ethernet header");
        return;
    }

    /* Skip over the Ethernet header. */
    packet += sizeof(struct ether_header);
    capture_len -= sizeof(struct ether_header);

    if (capture_len < sizeof(struct ip))
    { /* Didn't capture a full IP header */
        too_short(ts, "IP header");
        return;
    }

    ip = (struct ip*) packet;
    IP_header_length = ip->ip_hl * 4;       /* ip_hl is in 4-byte words */

    if (capture_len < IP_header_length)
    { /* didn't capture the full IP header including options */
        too_short(ts, "IP header with options");
        return;
    }

    if (ip->ip_p != IPPROTO_UDP)
    {
        problem_pkt(ts, "non-UDP packet");
        return;
    }

    /* Skip over the IP header to get to the UDP header. */
    packet += IP_header_length;
    capture_len -= IP_header_length;

    if (capture_len < sizeof(struct UDP_hdr))
    {
        too_short(ts, "UDP header");
        return;
    }

    udp = (struct UDP_hdr*) packet;

    printf("%s UDP src_port=%d dst_port=%d length=%d\n", 
            timestamp_string(ts), ntohs(udp->uh_sport), 
            ntohs(udp->uh_dport), ntohs(udp->uh_ulen));
}


int main(int argc, char *argv[])
{
    pcap_t *pcap;
    const unsigned char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    struct tcphdr *tcp;
    struct bpf_program fp;      /* The compiled filter */
    char filter_exp[] = "port 80";  /* The filter expression */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */

    /* Skip over the program name. */
    ++argv; --argc;

    /* We expect exactly one argument, the name of the file to dump. */
    if ( argc != 1 )
    {
        fprintf(stderr, "program requires one argument, the trace file to dump\n");
        exit(1);
    }

    pcap = pcap_open_offline(argv[0], errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
        exit(1);
    }

    /* Compile and apply the filter */
    if (pcap_compile(pcap, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        return(2);
    }

    if (pcap_setfilter(pcap, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        return(2);
    }

    /* Now just loop through extracting packets as long as we have
     * some to read.
     */
    while ((packet = pcap_next(pcap, &header)) != NULL)
    {
        process_tcp_packet(packet, header.ts, header.caplen);
    }
    return 0;
}


/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts)
{
    static char timestamp_string_buf[256];

    sprintf(timestamp_string_buf, "%d.%06d",
            (int) ts.tv_sec, (int) ts.tv_usec);

    return timestamp_string_buf;
}

void problem_pkt(struct timeval ts, const char *reason)
{
    fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
}

void too_short(struct timeval ts, const char *truncated_hdr)
{
    fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n", 
            timestamp_string(ts), truncated_hdr);
}

