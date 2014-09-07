#include <midhun-session.h>

void print_http_session(bool clientflag, unsigned char *cptr, int capture_len)
{

    for(int i=0;i<capture_len;i++)
    {
        if(cptr[i] >= 32 && cptr[i] < 127 || cptr[i] ==10)
            printf("%c", cptr[i]);
        else
        {
            switch(cptr[i])
            {
				case 13:
					break;
				case 9:
					//printf("%c", cptr[i]);
					break;
                default:
                    //printf("%u", cptr[i]);
					break;
            }
        }
    }
	cout<<"\n***************************************************************************************";
}

void print_telnet_session(bool clientflag, unsigned char *cptr, int capture_len)
{
    for(int i=0;i<capture_len;i++)
    {
        if(cptr[i] >= 32 && cptr[i] < 127 || cptr[i]=='\n' )
            printf("%c", cptr[i]);
        else
        {
			if(cptr[i]>=127 || cptr[i] <=31)
				continue;
            switch(cptr[i])
            {
				case 13:
					break;
                default:;
                    printf(" %u", cptr[i]);
            }
        }
    }
	cout<<"\n***************************************************************************************";
}

void print_ftp_session(bool clientflag, unsigned char *cptr, int capture_len)
{
    for(int i=0;i<capture_len;i++)
    {
        if(cptr[i] >= 32 && cptr[i] < 127 || cptr[i] == '\n')
            printf("%c", cptr[i]);
        else
        {
			continue;
            switch(cptr[i])
            {
				case 13:
					break;
                default:
                    printf(" %u", cptr[i]);
            }
        }
    }
	cout<<"\n***************************************************************************************";
}
void print_init(uint32_t th_seq, uint32_t th_ack, uint32_t capture_len)
{
	cout<<setw(17)<<"Seq : "<<ntohl(th_seq)<<"\n";
	cout<<setw(17)<<"Ack : "<<ntohl(th_ack)<<"\n";
	cout<<setw(17)<<"Payload size : "<<capture_len<<"\n";
	cout<<setw(17)<<"Payload :\n";
}

void process_tcp_packet(const unsigned char *packet, struct timeval ts,
		unsigned int capture_len)
{
	struct ip *ip;
	int i;
	const struct sniff_tcp *tcp;
	unsigned int IP_header_length;
	unsigned char *cptr;

	/* For simplicity, we assume Ethernet encapsulation. */

	if (capture_len < sizeof(struct ether_header))
	{
		/*
		 * We didn't even capture a full Ethernet header, so we
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
		//problem_pkt(ts, "non-TCP packet");
		return;
	}

	/* Skip over the IP header to get to the UDP header.*/
	packet += IP_header_length;
	capture_len -= IP_header_length;

	if (capture_len < sizeof(struct sniff_tcp))
	{
		too_short(ts, "TCP header");
		return;
	}

	tcp = (struct sniff_tcp *) packet;
	int size_tcp = TH_OFF(tcp)*4;
	cptr = (unsigned char *)packet;
	cptr += size_tcp;
	capture_len -= size_tcp;
	if(capture_len==0)
		return;

	int srcport = ntohs(tcp->th_sport);
	int dstport = ntohs(tcp->th_dport);

	switch(srcport)
	{
		case 80:
			cout<<"Server to client: \n";
			print_init(tcp->th_seq, tcp->th_ack, capture_len);
			print_http_session(SERVER, cptr, capture_len);
			cout<<"\n\n";
			break;
		case 23:
			cout<<"Server to client \n";
			print_init(tcp->th_seq, tcp->th_ack, capture_len);
			print_telnet_session(SERVER, cptr, capture_len);
			cout<<"\n\n";
			break;
		case 21:
			cout<<"Server to client \n";
			print_init(tcp->th_seq, tcp->th_ack, capture_len);
			print_ftp_session(SERVER, cptr, capture_len);
			cout<<"\n\n";
			break;
		default:
			break;
	}

	switch(dstport)
	{
		case 80:
			cout<<"Client to Server:\n";
			print_init(tcp->th_seq, tcp->th_ack, capture_len);
			print_http_session(CLIENT, cptr, capture_len);
			cout<<"\n\n";
			break;
		case 23:
			cout<<"Client to Server:\n";
			print_init(tcp->th_seq, tcp->th_ack, capture_len);
			print_telnet_session(CLIENT, cptr, capture_len);
			cout<<"\n\n";
			break;
		case 21:
			cout<<"Client to Server:\n";
			print_init(tcp->th_seq, tcp->th_ack, capture_len);
			print_ftp_session(CLIENT, cptr, capture_len);
			cout<<"\n\n";
			break;
		default:
			break;
	}
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
