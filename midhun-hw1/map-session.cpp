#include <map-session.h>


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

    int srcport = ntohs(tcp->th_sport);
    int dstport = ntohs(tcp->th_dport);
    if(capture_len == 0)
        return;

    unsigned char *diptr;
    diptr = (unsigned char*)packet - 2 * sizeof(struct in_addr); 

    char temp[200] = {'\0'};
    int len;
	string sessionkey;
	if(srcport ==80 || srcport ==23 || srcport == 21)
	{
		sessionkey = to_string(diptr[0]) + to_string(diptr[1]) + 
					 to_string(diptr[2]) + to_string(diptr[3]) + 
					 to_string(diptr[4]) + to_string(diptr[5]) + 
					 to_string(diptr[6]) + to_string(diptr[7]) + 
					 to_string(srcport) + to_string(dstport);
	} else {
		sessionkey = to_string(diptr[4]) + to_string(diptr[5]) + 
					 to_string(diptr[6]) + to_string(diptr[7]) + 
					 to_string(diptr[0]) + to_string(diptr[1]) + 
					 to_string(diptr[2]) + to_string(diptr[3]) + 
					 to_string(dstport) + to_string(srcport);
	}
	switch(srcport)
	{
		case 80:
			len = sprintf(temp, "\n\nHTTP Server %s to client  %d.%d.%d.%d \n"
					"SEQ num: %d \n Ack num: %d \n Payload \n",
					inet_ntoa(ip->ip_src), diptr[4], diptr[5], diptr[6], diptr[7],
					ntohl(tcp->th_seq), ntohl(tcp->th_ack));
			if(sessionmap.find(sessionkey) != sessionmap.end())
			{
				//update the file in the map
				FILE *fp = sessionmap.find(sessionkey)->second;
				fwrite(temp, sizeof(char), len, fp);
				fwrite(cptr, sizeof(char), capture_len, fp);
				uint32_t index = sessionindexmap.find(sessionkey)->second;
				index += capture_len+len;
				sessionindexmap.find(sessionkey)->second = index;
				sessionmap.insert(pair<string, FILE *>(sessionkey, fp));
			} else {
				//Create a new entry into the map
				FILE *fp = fopen(sessionkey.c_str(), "w+");
				fwrite(temp, sizeof(char), len, fp);
				fwrite(cptr, sizeof(char), capture_len, fp);
				sessionindexmap.insert(pair<string, uint32_t>(sessionkey, capture_len+len));
				sessionmap.insert(pair<string, FILE *>(sessionkey, fp));
			}
			break;
		case 23:
			len = sprintf(temp, "\n\nTELNET Server %s to client %d.%d.%d.%d \n"
					"SEQ num: %d \n Ack num: %d \n Payload \n",
					inet_ntoa(ip->ip_src), diptr[4], diptr[5], diptr[6], diptr[7],
					ntohl(tcp->th_seq), ntohl(tcp->th_ack));
			if(sessionmap.find(sessionkey) != sessionmap.end())
			{
				//update the file in the map
				FILE *fp = sessionmap.find(sessionkey)->second;
				fwrite(temp, sizeof(char), len, fp);
				fwrite(cptr, sizeof(char), capture_len, fp);
				uint32_t index = sessionindexmap.find(sessionkey)->second;
				index += capture_len+len;
				sessionindexmap.find(sessionkey)->second = index;
				sessionmap.insert(pair<string, FILE *>(sessionkey, fp));
			} else {
				//Create a new entry into the map
				FILE *fp = fopen(sessionkey.c_str(), "w+");
				fwrite(temp, sizeof(char), len, fp);
				fwrite(cptr, sizeof(char), capture_len, fp);
				sessionmap.insert(pair<string, FILE *>(sessionkey, fp));
				sessionindexmap.insert(pair<string, uint32_t>(sessionkey, capture_len+len));
			}
			break;
		case 21:
			len = sprintf(temp, "\n\nFTP Server %s to client %d.%d.%d.%d \n"
					"SEQ num: %d \n Ack num: %d \n Payload \n",
					inet_ntoa(ip->ip_src), diptr[0], diptr[1], diptr[2], diptr[3],
					ntohl(tcp->th_seq), ntohl(tcp->th_ack));
			if(sessionmap.find(sessionkey) != sessionmap.end())
			{
				//update the file in the map
				FILE *fp = sessionmap.find(sessionkey)->second;
				fwrite(temp, sizeof(char), len, fp);
				fwrite(cptr, sizeof(char), capture_len, fp);
				uint32_t index = sessionindexmap.find(sessionkey)->second;
				index += capture_len+len;
				sessionindexmap.find(sessionkey)->second = index;
				sessionmap.insert(pair<string, FILE *>(sessionkey, fp));
			} else {
				//Create a new entry into the map
				FILE *fp = fopen(sessionkey.c_str(), "w+");
				fwrite(temp, sizeof(char), len, fp);
				fwrite(cptr, sizeof(char), capture_len, fp);
				sessionmap.insert(pair<string, FILE *>(sessionkey, fp));
				sessionindexmap.insert(pair<string, uint32_t>(sessionkey, capture_len+len));
			}
			break;
		default:
			break;
	}

	switch(dstport)
	{
		case 80:
			len = sprintf(temp, "\n\nHTTP Client %s to server %d.%d.%d.%d \n"
					"SEQ num: %d \n Ack num: %d \n Payload :\n",
					inet_ntoa(ip->ip_src), diptr[0], diptr[1], diptr[2], diptr[3],
					ntohl(tcp->th_seq), ntohl(tcp->th_ack));
			if(sessionmap.find(sessionkey) != sessionmap.end())
			{
				//update the file in the map
				FILE *fp = sessionmap.find(sessionkey)->second;
				fwrite(temp, sizeof(char), len, fp);
				fwrite(cptr, sizeof(char), capture_len, fp);
				uint32_t index = sessionindexmap.find(sessionkey)->second;
				index += capture_len+len;
				sessionindexmap.find(sessionkey)->second = index;
				sessionmap.insert(pair<string, FILE *>(sessionkey, fp));
			} else {
				//Create a new entry into the map
				FILE *fp = fopen(sessionkey.c_str(), "w+");
				fwrite(temp, sizeof(char), len, fp);
				fwrite(cptr, sizeof(char), capture_len, fp);
				sessionmap.insert(pair<string, FILE *>(sessionkey, fp));
				sessionindexmap.insert(pair<string, uint32_t>(sessionkey, capture_len+len));
			}
			break;
		case 23:
			len = sprintf(temp, "\n\nTELNET Client %s to Server %d.%d.%d.%d \n"
					"SEQ num: %d \n Ack num: %d \n Payload \n",
					inet_ntoa(ip->ip_src), diptr[0], diptr[1], diptr[2], diptr[3],
					ntohl(tcp->th_seq), ntohl(tcp->th_ack));
			if(sessionmap.find(sessionkey) != sessionmap.end())
			{
				//update the file in the map
				FILE *fp = sessionmap.find(sessionkey)->second;
				fwrite(temp, sizeof(char), len, fp);
				fwrite(cptr, sizeof(char), capture_len, fp);
				uint32_t index = sessionindexmap.find(sessionkey)->second;
				index += capture_len+len;
				sessionmap.insert(pair<string, FILE *>(sessionkey, fp));
				sessionindexmap.find(sessionkey)->second = index;
			} else {
				//Create a new entry into the map
				FILE *fp = fopen(sessionkey.c_str(), "w+");
				fwrite(temp, sizeof(char), len, fp);
				fwrite(cptr, sizeof(char), capture_len, fp);
				sessionmap.insert(pair<string, FILE *>(sessionkey, fp));
				sessionindexmap.insert(pair<string, uint32_t>(sessionkey, capture_len+len));
			}
			break;
		case 21:
			len = sprintf(temp, "\n\nFTP Client %s to Server %d.%d.%d.%d \n"
					"SEQ num: %d \n Ack num: %d \n Payload \n ",
					inet_ntoa(ip->ip_src), diptr[0], diptr[1], diptr[2], diptr[3],
					ntohl(tcp->th_seq), ntohl(tcp->th_ack));
			if(sessionmap.find(sessionkey) != sessionmap.end())
			{
				//update the file in the map
				FILE *fp = sessionmap.find(sessionkey)->second;
				fwrite(temp, sizeof(char), len, fp);
				fwrite(cptr, sizeof(char), capture_len, fp);
				uint32_t index = sessionindexmap.find(sessionkey)->second;
				index += capture_len+len;
				sessionmap.insert(pair<string, FILE *>(sessionkey, fp));
				sessionindexmap.find(sessionkey)->second = index;
			} else {
				//Create a new entry into the map
				FILE *fp = fopen(sessionkey.c_str(), "w+");
				fwrite(temp, sizeof(char), len, fp);
				fwrite(cptr, sizeof(char), capture_len, fp);
				sessionmap.insert(pair<string, FILE *>(sessionkey, fp));
				sessionindexmap.insert(pair<string, uint32_t>(sessionkey, capture_len+len));
			}
			break;
		default:
			break;
	}
}

void print_sessions(void);


int main(int argc, char *argv[])
{
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	struct tcphdr *tcp;
	bpf_u_int32 mask;       /* Our netmask */
	bpf_u_int32 net;        /* Our IP */
	struct tcphdr thdr;

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
	//print_sessions();
	print_sessionmap();
	return 0;
}

void print_sessionmap(void)
{
	map<string, FILE *>::iterator it;
	it = sessionmap.begin();
	int session = 0;
	for(;it!=sessionmap.end();it++)
	{

		cout<<"\n\n***********************************************************************\n\n";
		cout<<"session begins\n\n";
		FILE *fp = it->second;
		rewind(fp);
		uint32_t index = sessionindexmap.find(it->first)->second,i=0;
		cout<<index;
		unsigned char c;
		do {
			c = (unsigned char)fgetc(fp);
			i++;
			if(c>=32 && c<=127 || c==10)
				printf("%c",c);
			else
				printf(" %d",c);
		} while(i<index);
		cout<<"\n\n\n\n\n\n";
	}
}

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

