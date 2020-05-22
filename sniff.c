#include<pcap.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<time.h>


#define IPPROTO_IP 0
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17



#define SNAP_LEN 1518							/* default snap length (maximum bytes per packet to capture) */
#define SIZE_ETHERNET 14						/* ethernet headers are always exactly 14 bytes [1] */
#define IP_HLEN(ip)	(((ip)->vhl) & 0x0f)		/*IP header length*/
#define IP_V(ip) 	(((ip)->vhl) >> 4)			/*IP Version*/


unsigned int CURR_PACKET_ID = 1;				/*The current number of packet*/



/*IPv4 address*/
typedef struct ip_address
{
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
	unsigned char byte4;
}ip_addr;

/*Mac address*/
typedef struct mac_address
{
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
	unsigned char byte4;
	unsigned char byte5;
	unsigned char byte6;
}mac_addr;

/*Ethernet frame header*/
typedef struct ethernet_header
{
	mac_addr mac_dest_addr;
	mac_addr mac_source_addr;
	unsigned short type;
}eth_header;


/*IPv4 header*/
typedef struct ip_header
{
	unsigned char vhl; 			/*version(4 bits) & header length(4 bits)*/
	unsigned char tos; 			/*type of service*/
	#define IP_TOS_DSF 0xfc		/*1111 1100*/
	#define IP_TOS_R 0x03		/*0000 0011*/
	unsigned short len;			/*total length*/
	unsigned short id;			/*identification*/
	unsigned short off;			/*Flags(3 bits) + Fragment offset(13 bits)*/
	#define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFSET 0x1fff    /* mask for fragmenting bits */
	unsigned char ttl;			/*time to live*/
	unsigned char proto;		/*protocol*/
	unsigned short checksum;	/*checksum*/
	ip_addr ip_src_addr;		/*source ip address*/
	ip_addr ip_des_addr;		/*destination ip address*/
	//unsigned int op_pad[10];	/*Option + Padding(0~40 Bytes)*/
}ip_header;

typedef struct udp_header
{
	unsigned short sport;		/*source port*/
	unsigned short dport;		/*destination port*/
	unsigned short len; 		/*total length*/
	unsigned short checksum;  	/*checksum*/
}udp_header;

typedef struct tcp_header
{
	unsigned short sport;		/**/
	unsigned short dport;		/**/
	unsigned int seq;   		/**/
	unsigned int ack;			/**/
	/*... ...*/
}tcp_header;




/*pcap_handler callback*/
void capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/*display the ip header infomations*/
void show_ip_header(ip_header *ip, const struct pcap_pkthdr *header);

/*dec to show binary, such as (.... 0000) or (0000 00..) or offset(...0 0000 0000 0000)*/
void binary(int , char *);

/*ip header field(total length) */
unsigned short convert(unsigned short value);

unsigned convert_int(char *);

void usage()
{
	printf("Usage: XSniff [-n count] [-f proto]\n");
	printf("\n");
	printf("Options:\n");
	printf("       -n    positive integer|capture packet count.\n");
	printf("       -f    string|protocol you want to filter. ip(Default)\n");
	printf("             such as ip, udp, tcp or icmp etc...\n");
	printf("\n");
	exit(0);
} 

int main(int argc, char **argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	int i=0;
	int choice;
	unsigned mask;						/* subnet mask */
	unsigned net;						/*device net */
	ip_addr *net_ip,*netmask;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;						/* packet capture handle */
	struct bpf_program fp;				/* compiled filter program (expression) */
	char filter_exp[20] = "ip";			/* filter expression */
	int CAPTURE_COUNT = 0;				/*capture packet count,-1 or 0 equivalent to infinity */
	
	switch(argc)
	{
		case 1:
			/* default filter protocol is ip*/
			break;
		case 3:
			if(strcmp(argv[1],"-f")==0)
				strcpy(filter_exp,argv[2]);
			else if(strcmp(argv[1],"-n")==0)
				CAPTURE_COUNT = convert_int(argv[2]);
			else
				usage();
			break;
		case 5:
			if(strcmp(argv[1],"-f")==0)
			{
				strcpy(filter_exp,argv[2]);
				if(strcmp(argv[3],"-n")==0)
					CAPTURE_COUNT = convert_int(argv[4]);
				else
					usage();
			}
			else if(strcmp(argv[1],"-n")==0)
			{
				CAPTURE_COUNT = convert_int(argv[2]);
				if(strcmp(argv[3],"-f")==0)
					strcpy(filter_exp,argv[4]);
				else
					usage();
			}
			break;
		default:
			usage();
			break;
	}
	

	
	
	/*find all interfaces devs, if not found, exit*/
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs:%s\n",errbuf);
		exit(1);
	}
	for(dev=alldevs;dev!=NULL;dev=dev->next)
	{
		printf("%d. %s", ++i, dev->name);
        if (dev->description)
            printf(" (%s)\n", dev->description);
        else
            printf(" (No description available)\n");
	}
	
	/*No interfaces found*/
	if(i == 0)
	{
		printf("No interfaces found!\n");
        return -1;
	}
	
	/*Choice the interface form list*/
	printf("Enter the interface number (1-%d):",i);
    scanf("%d", &choice);
    
    /*Choice failure*/
    if(choice<1 || choice>i)
    {
    	printf("Interface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
	}
	
	/*assign dev*/
	for(dev=alldevs,i=1;i<choice;i++,dev=dev->next);
	
	/* get network number and mask associated with capture device */
	if(pcap_lookupnet(dev->name, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",dev->name, errbuf);
		net = 0;
		mask = 0;
	}
	
	/*
	pcap_t * pcap_open_live(const char * device£¬int snaplen, int promisc, int to_ms, char * errbuf); 
	
	device:  on Linux systems with 2.2 or later kernels, a device argument of "any" or NULL can be used to capture packets from all interfaces.
	snaplen: specifies the snapshot length to be set on the handle.
	promisc: specifies if the interface is to be put into promiscuous mode.
	to_ms:   specifies the packet buffer timeout, as a non-negative value, in milliseconds.
	*/
	handle = pcap_open_live(dev->name, SNAP_LEN, 1, 1000, errbuf);
	if(handle==NULL)	/*Couldn't open device*/
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
		exit(1);
	}
	
	/* make sure we're capturing on an Ethernet device */
	if(pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "%s is not an Ethernet\n", dev->name);
		exit(1);
	}
	
	net_ip = (ip_addr *)&net;
	netmask = (ip_addr *)&mask;
	
	printf("\nListening for data through %s...\n",dev->name);
	printf("Device: %s\n",dev->name);
	printf("Network: %d.%d.%d.%d	Mask: %d.%d.%d.%d\n",
		net_ip->byte1,net_ip->byte2,net_ip->byte3,net_ip->byte4,
		netmask->byte1,netmask->byte2,netmask->byte3,netmask->byte4
		);
	printf("Filter: %s\n",filter_exp);
	if (CAPTURE_COUNT == 0)
		printf("Capture count: Infinity\n");
	else
		printf("Capture count: %d\n",CAPTURE_COUNT);
	
	
	
	
	/*log start*/ 
	FILE *filep;
	if((filep=fopen("capture.log", "a+"))==NULL)
	{
		fprintf(stderr, "File open Failure.\n");
		exit(1);
	}
	fprintf(filep,"\n\n\nListening for data through %s...\n",dev->name);
	fprintf(filep,"Device: %s\n",dev->name);
	fprintf(filep,"Network: %d.%d.%d.%d	Mask: %d.%d.%d.%d\n",
		net_ip->byte1,net_ip->byte2,net_ip->byte3,net_ip->byte4,
		netmask->byte1,netmask->byte2,netmask->byte3,netmask->byte4
		);
	fprintf(filep,"Filter: %s\n",filter_exp);
	if (CAPTURE_COUNT == 0)
		fprintf(filep,"Capture count: Infinity\n");
	else
		fprintf(filep,"Capture count: %d\n",CAPTURE_COUNT);
	
	if(fclose(filep)!=0)
	{
		fprintf(stderr, "File Close Failure.\n");
		exit(1);
	}
	/*log end*/
	
	
	
	/*free devices memory*/
	pcap_freealldevs(alldevs);
	
	
	/*set filter;*/
	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(1);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(1);
	}
	
	
	/*
	int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
	cnt = -1 or 0 equivalent to infinity 
	*/
	pcap_loop(handle, CAPTURE_COUNT, capture, NULL);	/* start capture */
	
	return 0;
}

/*Callback function, which is called by Libpcap when each packet is received*/
void capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	ip_header * ip;
	eth_header *eth;
	int length = 0;
	
	
	eth = (eth_header *)packet;
	ip = (ip_header *)(packet+SIZE_ETHERNET);
	length = IP_HLEN(ip)*4;
	if(length < 20)
	{
		printf("\n   * Invalid IP header length: %u bytes\n", length);
		return;
	}
	
	
	show_ip_header(ip,header);
	
}

void show_ip_header(ip_header *ip, const struct pcap_pkthdr *header)
{
	char *proto;
	ip->off = convert(ip->off); 
	int rf = ip->off&IP_RF ? 1 : 0;		/*Reserved bit*/
	int df = ip->off&IP_DF ? 1 : 0;		/*Don't Fragment*/
	int mf = ip->off&IP_MF ? 1 : 0;		/*More Fragment*/
	int offset = ip->off&IP_OFFSET;		/*Offset*/
	
	unsigned char binary_str[20] = "...0 0000 0000 0000";
	unsigned char binary_dsf[] = "0000 00..";
	unsigned char binary_dsf_r[] = ".... ..00";
	binary(offset, binary_str+18);
	binary(ip->tos&IP_TOS_DSF/4,binary_dsf+6);
	binary(ip->tos&IP_TOS_R,binary_dsf_r+6);
	
	
	
	struct tm *ltime;
    char timestr[30];
    time_t local_tv_sec;
    
    /* time */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%y-%m-%d %H:%M:%S", ltime);
    printf("\n");
    printf("%s,  len:%d\n", timestr, header->len);
	
	FILE *fp;
	if((fp=fopen("capture.log", "a+"))==NULL)
	{
		fprintf(stderr, "File open Failure.\n");
		exit(1);
	}
	
	
	switch(ip->proto)
	{
		case IPPROTO_TCP:
			proto = "TCP";
			break;
		case IPPROTO_UDP:
			proto = "UDP";
			break;
		case IPPROTO_ICMP:
			proto = "ICMP";
			break;
		case IPPROTO_IP:
			proto = "IP";
			break;
		default:
			proto = "unknown";
			break;
	}
	printf("***************************%d***************************\n",CURR_PACKET_ID);
	printf("Version: %d\n",IP_V(ip));
	printf("Header Length: %d bytes (%d)\n",IP_HLEN(ip)*4,IP_HLEN(ip));
	/*tos*/
	printf("Differentiated Services Field: 0x%x\n",ip->tos);
	printf("  %s = Differentiated Services Codepoint: %d\n", binary_dsf, ip->tos&IP_TOS_DSF/4 );
	printf("  %s = Explicit Congestion Notification: %d\n", binary_dsf_r, ip->tos&IP_TOS_R );
	printf("Total Length: %u\n",convert(ip->len));
	printf("Identification: 0x%x (%d)\n",ip->id,ip->id);
	/*flags*/
	printf("Flags: 0x%x\n",ip->off);
	printf("  %d... .... .... .... = Reserved bit : %s\n", rf, rf==0 ? "Not set" : "Set");
	printf("  .%d.. .... .... .... = Don't Fragment : %s\n",df, df==0 ? "Not set" : "Set");
	printf("  ..%d. .... .... .... = More Fragments : %s\n", mf, mf==0 ? "Not set" : "Set");
	printf("  %s = Fragment offset : %d\n",binary_str, offset);
	printf("Time to live : %d\n",ip->ttl);
	printf("Protocol: %s (%d)\n",proto,ip->proto);
	printf("Header checksum: 0x%x\n",ip->checksum);
	printf("  [Header checksum status: Unverified]\n");
	printf("Source: %d.%d.%d.%d\n",ip->ip_src_addr.byte1,ip->ip_src_addr.byte2,ip->ip_src_addr.byte3,ip->ip_src_addr.byte4);
	printf("Destination: %d.%d.%d.%d\n",ip->ip_des_addr.byte1,ip->ip_des_addr.byte2,ip->ip_des_addr.byte3,ip->ip_des_addr.byte4);
	
	
	
	/*write log*/
	fprintf(fp, "\n%s,  Packet len:%d\n", timestr, header->len);
	fprintf(fp,"***************************%d***************************\n",CURR_PACKET_ID);
	fprintf(fp,"Version: %d\n",IP_V(ip));
	fprintf(fp,"Header Length: %d bytes (%d)\n",IP_HLEN(ip)*4,IP_HLEN(ip));
	/*tos*/
	fprintf(fp,"Differentiated Services Field: 0x%x\n",ip->tos);
	fprintf(fp,"  %s = Differentiated Services Codepoint: %d\n", binary_dsf, ip->tos&IP_TOS_DSF/4 );
	fprintf(fp,"  %s = Explicit Congestion Notification: %d\n", binary_dsf_r, ip->tos&IP_TOS_R );
	fprintf(fp,"Total Length: %u\n",convert(ip->len));
	fprintf(fp,"Identification: 0x%x (%d)\n",ip->id,ip->id);
	/*flags*/
	fprintf(fp,"Flags: 0x%x\n",ip->off);
	fprintf(fp,"  %d... .... .... .... = Reserved bit : %s\n", rf, rf==0 ? "Not set" : "Set");
	fprintf(fp,"  .%d.. .... .... .... = Don't Fragment : %s\n",df, df==0 ? "Not set" : "Set");
	fprintf(fp,"  ..%d. .... .... .... = More Fragments : %s\n", mf, mf==0 ? "Not set" : "Set");
	fprintf(fp,"  %s = Fragment offset : %d\n",binary_str, offset);
	fprintf(fp,"Time to live : %d\n",ip->ttl);
	fprintf(fp,"Protocol: %s (%d)\n",proto,ip->proto);
	fprintf(fp,"Header checksum: 0x%x\n",ip->checksum);
	fprintf(fp,"  [Header checksum status: Unverified]\n");
	fprintf(fp,"Source: %d.%d.%d.%d\n",ip->ip_src_addr.byte1,ip->ip_src_addr.byte2,ip->ip_src_addr.byte3,ip->ip_src_addr.byte4);
	fprintf(fp,"Destination: %d.%d.%d.%d\n",ip->ip_des_addr.byte1,ip->ip_des_addr.byte2,ip->ip_des_addr.byte3,ip->ip_des_addr.byte4);
	
	if(fclose(fp)!=0)
	{
		fprintf(stderr, "File Close Failure.\n");
		exit(1);
	}
	
	CURR_PACKET_ID++;
}


void binary(int dec, char *str)
{
	int temp = 0;
	while(dec)
	{
		temp = dec%2;
		if (*str == '0')
			*str-- = temp + '0';
		else
		{
			*str--;
			continue;
		}
		dec = dec/2;
	}
}

unsigned short convert(unsigned short value)
{
    return ((value & 0x00FF) << 8 ) | ((value & 0xFF00) >> 8);
}

unsigned convert_int(char *str)
{
	int i = 0;
	unsigned num=0;
	for(i=0;i<strlen(str);i++)
	{
		if(str[i]<'0'||str[i]>'9')
			usage();
	}
	
	for(i=0;i<strlen(str);i++)
		num = num*10 + (str[i]-'0');
	
	return num;
	
}
