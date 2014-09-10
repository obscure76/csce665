#include <midhun-session.h>

void print_init(uint32_t th_seq, uint32_t th_ack, uint32_t capture_len, unsigned char *cptr)
{
	cout<<setw(17)<<"Seq : "<<ntohl(th_seq)<<"\n";
	cout<<setw(17)<<"Ack : "<<ntohl(th_ack)<<"\n";
	cout<<setw(17)<<"Payload size : "<<capture_len<<"\n";
	cout<<setw(17)<<"Payload :\n";
	for(int i=0;i<capture_len;i++)
	{
        if(cptr[i] >= 32 && cptr[i] < 127 || cptr[i] ==10)
            printf("%c", cptr[i]);
		else
		{
			//Displaying ascii num of unreadable char
			printf(" %d", cptr[i]);
		}
	}
	cout<<"\n***************************************************************************************";
}

void print_http_session(bool clientflag, unsigned char *cptr, int capture_len, struct in_addr addr, char *str, int len)
{
	/* Check if a session exists for this client */
	list<session_info>::iterator it;
	for(it=httplist.begin();it!=httplist.end();it++)
	{
		if(it->client_addr == addr.s_addr)
		{
			/* There was a started session ; update current info */
			for(int i =0;i<capture_len;i++)
			{
                FILE *fp = it->fp;
                uint32_t index = it->index;
                fwrite(str, sizeof(char), len, fp);
                fwrite(cptr, sizeof(char), capture_len, fp);
                it->index += capture_len+len;
                return;
			}
		} else {
			//cout<<it->client_addr<<endl;
		}
	}
	/* New session, create one */
	session_info session;
	session.client_addr = addr.s_addr;
	session.index = 0;
    string fname = to_string(addr.s_addr) + to_string(HTTP);
    session.fp = fopen(fname.c_str(), "w+");
    fwrite(str, sizeof(char), len, session.fp);
    fwrite(cptr, sizeof(char), capture_len, session.fp);
    session.index+=capture_len+len;
    httplist.push_back(session);
}

void print_telnet_session(bool clientflag, unsigned char *cptr, int capture_len, struct in_addr addr, char *str, int len)
{
    list<session_info>::iterator it;
    for(it=telnetlist.begin();it!=telnetlist.end();it++)
    {
        if(it->client_addr == addr.s_addr)
        {
            FILE *fp = it->fp;
            uint32_t index = it->index;
            fwrite(str, sizeof(char), len, fp);
            fwrite(cptr, sizeof(char), capture_len, fp);
            it->index += capture_len+len;
            return;
        }
    }
    session_info session;
    session.client_addr = addr.s_addr;
    session.index = 0;
    string fname = to_string(addr.s_addr)+to_string(TELNET);
    session.fp = fopen(fname.c_str(), "w+");
    fwrite(str, sizeof(char), len, session.fp);
    fwrite(cptr, sizeof(char), capture_len, session.fp);
    session.index+=capture_len+len;
    telnetlist.push_back(session);
}

void print_ftp_session(bool clientflag, unsigned char *cptr, int capture_len, struct in_addr addr, char *str, int len)
{
    list<session_info>::iterator it;
    for(it=ftplist.begin();it!=ftplist.end();it++)
    {
        if(it->client_addr == addr.s_addr)
        {
            /* There was a started session ; update current info */
            FILE *fp = it->fp;
            uint32_t index = it->index;
            fwrite(str, sizeof(char), len, fp);
            fwrite(cptr, sizeof(char), capture_len, fp);
            it->index += capture_len+len;
            return;
        }
    }
    /* New session, create one */
    session_info session;
    session.client_addr = addr.s_addr;
    session.index = 0;
    string fname = to_string(addr.s_addr)+to_string(FTP);
    session.fp = fopen(fname.c_str(), "w+");
    fwrite(str, sizeof(char), len, session.fp);
    fwrite(cptr, sizeof(char), capture_len, session.fp);
    session.index += capture_len+len;
    ftplist.push_back(session);
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
    diptr = (unsigned char*)packet - sizeof(struct in_addr); 

    char temp[200] = {'\0'};
    int len;
    switch(srcport)
    {
        case 80:
            len = sprintf(temp, "\n\nHTTP Server %s to client  %d.%d.%d.%d \n"
                    "SEQ num: %d \n Ack num: %d \n Payload \n",
                    inet_ntoa(ip->ip_src), diptr[3], diptr[2], diptr[1], diptr[0],
                    ntohl(tcp->th_seq), ntohl(tcp->th_ack));
            print_http_session(SERVER, cptr, capture_len, ip->ip_dst, temp, len);
            break;
        case 23:
            len = sprintf(temp, "\n\nTELNET Server %s to client %d.%d.%d.%d \n"
                    "SEQ num: %d \n Ack num: %d \n Payload \n",
                    inet_ntoa(ip->ip_src), diptr[0], diptr[1], diptr[2], diptr[3],
                    ntohl(tcp->th_seq), ntohl(tcp->th_ack));
            print_telnet_session(SERVER, cptr, capture_len, ip->ip_dst, temp, len);
            break;
        case 21:
            len = sprintf(temp, "\n\nFTP Server %s to client %d.%d.%d.%d \n"
                    "SEQ num: %d \n Ack num: %d \n Payload \n",
                    inet_ntoa(ip->ip_src), diptr[0], diptr[1], diptr[2], diptr[3],
                    ntohl(tcp->th_seq), ntohl(tcp->th_ack));
            print_ftp_session(SERVER, cptr, capture_len, ip->ip_dst, temp, len);
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
            print_http_session(CLIENT, cptr, capture_len, ip->ip_src, temp, len);
            break;
        case 23:
            len = sprintf(temp, "\n\nTELNET Client %s to Server %d.%d.%d.%d \n"
                    "SEQ num: %d \n Ack num: %d \n Payload \n",
                    inet_ntoa(ip->ip_src), diptr[0], diptr[1], diptr[2], diptr[3],
                    ntohl(tcp->th_seq), ntohl(tcp->th_ack));
            print_telnet_session(CLIENT, cptr, capture_len, ip->ip_src, temp, len);
            break;
        case 21:
            len = sprintf(temp, "\n\nFTP Client %s to Server %d.%d.%d.%d \n"
                    "SEQ num: %d \n Ack num: %d \n Payload \n ",
                    inet_ntoa(ip->ip_src), diptr[0], diptr[1], diptr[2], diptr[3],
                    ntohl(tcp->th_seq), ntohl(tcp->th_ack));
            print_ftp_session(CLIENT, cptr, capture_len, ip->ip_src, temp, len);
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
    print_sessions();
    return 0;
}

void print_sessions(void)
{
    list<session_info>::iterator it;
    cout<<"HTTP sessions\n\n";
    for(it=httplist.begin();it!=httplist.end();it++)
    {
        rewind(it->fp);
        unsigned char c;
        int i=0;
        do {
            c = (unsigned char)fgetc(it->fp);
            i++;
            if(c>=32 && c<=127 || c==10)
                printf("%c", c);
            else
                printf(" %d", c);
        } while (i<it->index);
        cout<<endl;
        cout<<endl;
        cout<<endl;
    }

    cout<<"TELNET sessions\n\n";
    for(it=telnetlist.begin();it!=telnetlist.end();it++)
    {
        rewind(it->fp);
        unsigned char c;
        int i=0;
        do {
            c = (unsigned char)fgetc(it->fp);
            i++;
            if(c>=32 && c<=127 || c==10)
                printf("%c", c);
            else
                printf(" %d", c);
        } while (i<it->index);
        cout<<endl;
        cout<<endl;
        cout<<endl;
    }

    cout<<"FTP sessions\n\n";
    for(it=ftplist.begin();it!=ftplist.end();it++)
    {
        rewind(it->fp);
        unsigned char c;
        int i=0;
        do {
            c = (unsigned char)fgetc(it->fp);
            i++;
            if(c>=32 && c<=127 || c==10)
                printf("%c", c);
            else
                printf(" %d", c);
        } while (i<it->index);
        cout<<endl;
        cout<<endl;
        cout<<endl;
    }
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

