#include<stdio.h>
#include<pcap.h>
#include<stdlib.h>

int main(int argc, char** argv)
{       
    char *dev, *error_openoffline, *fname, *gen_error;
    pcap_t *desc;//declaring the decsriptor 
    pcap_dumper_t   *pd;
    struct pcap_pkthdr *header;//declaring packet header
    u_char *sp;//packet data written to savefile    

    dev="eth1";//setting the device as eth1
    fname=argv[1];

    desc=pcap_open_offline( fname, error_openoffline );
    if( desc == NULL )
    {
        printf("The session could not open as %s", error_openoffline );         
        exit(1);
    }

    pd=pcap_dump_open( desc, fname );
    if( pd == NULL )
    {       gen_error=pcap_geterr( desc );
        printf( "\nThe dump could not be opened as %s", gen_error );
        exit(1);        
    }

    pcap_dump( (u_char *) pd, header, sp);

    printf("\nThe data is %h", sp );
    printf("\nThe data is %s", sp );

    pcap_dump_close( pd );
    pcap_close( desc );

    return 0;

}
