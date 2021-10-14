#include <stdio.h>				//////////////////////////
#include <signal.h>				//						//
#include <stdlib.h> 			//						//
#include <stdbool.h>			//						//
#include <ctype.h>				//	C-dependencies		//
#include <string.h>				//						//
#include <getopt.h>				//						//
#include <time.h>				//						//
#include <sys/types.h>			//////////////////////////
#include <netdb.h>				//////////////////////////
#include <arpa/inet.h>			//						//
#include <pcap.h>				//						//
#include <netinet/ip.h>			//						//
#include <netinet/ip_icmp.h>	//						//
#include <netinet/icmp6.h>		//						//
#include <netinet/tcp.h>		// Libs for sniffing 	//
#include <netinet/udp.h>		//						//
#include <netinet/ip_icmp.h>	//						//
#include <netinet/if_ether.h>	//						//
#include <netinet/ip6.h> 		//////////////////////////


typedef struct pckt_info 
{
    char src_addr[1025];
    char dest_addr[1025];
    unsigned src_port;
    unsigned dest_port;
	int proto_type;
} pckt_info;


int PNUM = 1;
int LOOPS = 1;
char errbuf[PCAP_ERRBUF_SIZE];


void exit_with_message(char* message, int exit_code){
    perror(message);
    exit(exit_code);
}

void print_help(){
    printf(
        "./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n"
        "kde:\n"
        "\t-i device (právě jedno rozhraní, na kterém se bude poslouchat. Nebude-li tento parametr uveden, či bude-li uvedené jen -i bez hodnoty, vypíše se seznam aktivních rozhraní)\n"
        "\t-p number (bude filtrování paketů na daném rozhraní podle portu; nebude-li tento parametr uveden, uvažují se všechny porty;"
		"pokud je parametr uveden, může se daný port vyskytnout jak v source, tak v destination části)\n"
        "\t-n 10 (určuje počet paketů, které se mají zobrazit; pokud není uvedeno, uvažujte zobrazení pouze jednoho paketu)\n"
        "Protokoly:\n"
        "\t-t nebo --tcp (bude zobrazovat pouze TCP pakety)\n"
        "\t-u nebo --udp (bude zobrazovat pouze UDP pakety)\n"
        "\t--icmp (bude zobrazovat pouze ICMPv4 a ICMPv6 pakety)\n"
        "\t--arp (bude zobrazovat pouze ARP rámce)\n"
        "\t(Pokud nebudou konkrétní protokoly specifikovány, uvažují se k tisknutí všechny (tj. veškerý obsah, nehledě na protokol))\n"
        "Argumenty mohou být v libovolném pořadí\n"
    );
    
    exit(1);
}

void interrupt_handler(){
    printf("Program interrupted via keyboard, finishing...");
    exit(-1);
}

void get_time(char *time, const struct pcap_pkthdr* pkthdr)
{
	size_t len = strftime(time, 100, "%Y-%m-%dT%H:%M:%S%z", localtime(&pkthdr->ts.tv_sec));
	if (len)
	{
		char zone[] = {time[len-5], time[len-4], time[len-3], ':', time[len-2], time[len-1], '\0'};
		sprintf(time+len-5, ".%li%s", pkthdr->ts.tv_usec, zone);
	}
}

void print_data(char *time, pckt_info packet, 
				const unsigned data_len, const u_char *data)
{
	if (packet.proto_type == 6 || packet.proto_type == 17)
	{
		printf("%s %s:%u > %s:%u, length: %u\n",
			   time, packet.src_addr, packet.src_port, 
		       packet.dest_addr, packet.dest_port, data_len);
	}
	else
	{
		printf("%s %s > %s length: %u\n",
			   time, packet.src_addr,
			   packet.dest_addr, data_len);
	}
	printf("--------------------------------------------------------------------------\n");

	for (unsigned int i = 0; i <= data_len; i += 16) 
	{
		// offset of given bytes
		printf("0x%04x", i);

		// given byte in hex
		for (int k = 0; k < 16; k++)
		{
			if (k == 8)
				printf(" ");

			if (i+k >= data_len)
				printf("   ");
			else
				printf(" %02x", data[i+k]);
        }

        printf("  ");

		// given byte in ASCII, if it's not printable, it will print a dot
        for (int k = 0; k < 16; k++)
		{
			if (k == 8)
				printf(" ");

			if (i+k == data_len)
				break;
			else
				printf("%c", isprint(data[i+k]) ? data[i+k] : '.');			
        }
        printf("\n");
    }   

	printf("--------------------------------------------------------------------------\n\n");
    
}

char *host_name(struct in_addr ip_addr)
{
	char *ip = malloc(NI_MAXHOST * sizeof(char));
	if (!ip) 
		exit(1);

	if (inet_ntop(AF_INET, &ip_addr, ip, NI_MAXHOST) == NULL)
	{
		perror("inet_ntoa"); 
		exit(1);
	}

	return ip;
}

char *host_nameIPv6(struct in6_addr ip_addr)
{
	char *ip = malloc(NI_MAXHOST * sizeof(char));
	if (!ip) 
		exit(1);

	if (inet_ntop(AF_INET6, &ip_addr, ip, NI_MAXHOST) == NULL)
	{
		perror("inet_ntop"); 
		exit(1);
	}

	return ip;
}

pckt_info process_arp_ether(const u_char* buffer)
{
	LOOPS++;

	pckt_info packet = {.proto_type = -1};
	struct ether_arp *arph = (struct ether_arp *)(buffer + 14);
	sprintf(packet.src_addr, "%u:%u:%u:%u", arph->arp_spa[0],
											arph->arp_spa[1],
											arph->arp_spa[2], 
											arph->arp_spa[3]);
	sprintf(packet.dest_addr, "%u:%u:%u:%u", arph->arp_tpa[0],
											 arph->arp_tpa[1],
											 arph->arp_tpa[2], 
											 arph->arp_tpa[3]);
	
	return packet;
}

pckt_info process_ip_ether(const u_char* buffer, bool ipv6)
{
	LOOPS++;

	pckt_info packet;
	struct tcphdr *tcph;
	struct udphdr *udph;
    unsigned iphdr_len, protocol_num = 0;
    char *src = NULL, *dest = NULL;

    if (ipv6)
    {
    	struct ip6_hdr* iph = (struct ip6_hdr *)(buffer + sizeof(struct ether_header));

		iphdr_len = 40;
		protocol_num = iph->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    	src = host_nameIPv6(iph->ip6_src);
    	dest = host_nameIPv6(iph->ip6_dst);
    }
    else
    {	
    	struct ip* iph = (struct ip *)(buffer + sizeof(struct ether_header));

		iphdr_len = iph->ip_hl*4;
		protocol_num = iph->ip_p;
    	src = host_name(iph->ip_src);
    	dest = host_name(iph->ip_dst);
    }

	strcpy(packet.src_addr, src), free(src);
	strcpy(packet.dest_addr, dest), free(dest);
	packet.proto_type = protocol_num;

	switch (protocol_num)
	{
		case 1: case 58:
			break;
		
		case 6:
			tcph = (struct tcphdr*)(buffer + iphdr_len + sizeof(struct ether_header));
			
			packet.src_port = ntohs(tcph->th_sport);
			packet.dest_port = ntohs(tcph->th_dport);
			break;
		
		case 17:
			udph = (struct udphdr*)(buffer + iphdr_len + sizeof(struct ether_header));   

			packet.src_port = ntohs(udph->uh_sport);
			packet.dest_port = ntohs(udph->uh_dport);
			break;
		
		default:
			printf("Given protocol number %d is unrecognized, ignoring\n", protocol_num);
			break;
	}

	return packet;
}


void callback(u_char *user, const struct pcap_pkthdr* pkthdr, const u_char* buffer)
{
	signal(SIGINT, interrupt_handler);

	pckt_info packet;
    const unsigned int data_len = (pkthdr->len);

	char time[100];
	get_time(time, pkthdr);

	struct ether_header *p = (struct ether_header *) buffer;
	uint16_t eth_type = ntohs(p->ether_type);
	switch (eth_type)
	{
		case ETHERTYPE_ARP:
			packet = process_arp_ether(buffer);
			break;

		case ETHERTYPE_IPV6:
			packet = process_ip_ether(buffer, true);
			break;
		
		case ETHERTYPE_IP:
			packet = process_ip_ether(buffer, false);
			break;

		default:
			printf("Unrecognized ether type: %d\n", eth_type);
			return;
	}

	print_data(time, packet, data_len, buffer);

    if (LOOPS > PNUM) {
    	exit(0);
    }	
}

void print_devices()
{
	pcap_if_t *alldevs, *dlist;
	int i = 0;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
		exit_with_message(strcat("Error when getting list of devices: ", errbuf), 1);

	printf("-------------------- Available interfaces: --------------------\n");
	for(dlist=alldevs; dlist; dlist=dlist->next)
	{
		printf("%d. device: %s", ++i, dlist->name);
		if (dlist->description)
			printf(" (%s)\n", dlist->description);
		else
			printf("(No description)\n");
	}

	pcap_freealldevs(alldevs);
	exit(0);
}

void create_filter(char *filter, char *port, bool arp, bool icmp, bool tcp, bool udp)
{
	if ((arp == icmp) && (arp == tcp) && (arp == udp)){
		if (*port)
			sprintf(filter, "arp or icmp or icmp6 or tcp port %s or udp port %s", port, port);
		else
			sprintf(filter, "arp or icmp or icmp6 or tcp or udp");
		
		printf("filter: %s\n", filter);
		return;
	}

	if (arp) {
		strcat(filter, "arp");
	}
	if (icmp) {
		if (*filter)
			strcat(filter, " or ");

		strcat(filter, "icmp or icmp6");
	}
	if (tcp) {
		if (*filter)
			strcat(filter, " or ");

		strcat(filter, "tcp");

		if (*port){
			strcat(filter, " port ");
			strcat(filter, port);
		}
	}
	if (udp) {
		if (*filter)
			strcat(filter, " or ");

		strcat(filter, "udp");

		if (*port){
			strcat(filter, " port ");
			strcat(filter, port);
		}
	}

	printf("filter: %s\n", filter);

	return;
}

void parse_args(int argc, char** argv, char* interface, char* port,
				bool* arp, bool* icmp, bool* tcp, bool* udp, int* pnum)
{
	char *mod;
	struct option longopts[] = {{"interface", required_argument, 0, 'i'},
								{"tcp", no_argument, 0, 't'},
								{"udp", no_argument, 0, 'u'},
        						{"arp", no_argument, 0, 'a'},
								{"icmp", no_argument, 0, 'c'}};

	while (true) 
	{
		int opt = getopt_long(argc, argv, "i:p:n:tuh", longopts, NULL);
		if (opt == -1)
			break;

		switch (opt) {
            case 'i':
				strcpy(interface, optarg);
                break;
            case 'p':
                strcpy(port, optarg);
                break;
            case 'n':
                *pnum = strtol(optarg, &mod, 10);
                if (*mod)
                    exit_with_message("Given number of packets is not integer!", 1);

                break;
            case 't':
                *tcp = true;
                break;
            case 'u':
                *udp = true;
                break;
            case 'a':
                *arp = true;
                break;
            case 'c':
                *icmp = true;
                break;
            case 'h':
				print_help();
				return;
            default:
                fprintf(stderr, "Undefined argument: %d\n", opt);
                print_help();
				return;
        }
	}
}

int main(int argc, char *argv[])
{
	char interface[20] = "", port[15] = "";
	int pnum = 1;
	bool arp = false, icmp = false,
		 tcp = false, udp = false;
	
	parse_args(argc, argv, interface, port, &arp, &icmp, &tcp, &udp, &pnum);
   	PNUM = pnum;

	if (!*interface)
		print_devices();

	char temp[500];
	struct bpf_program fp;
	bpf_u_int32 pMask, pNet;

	if (pcap_lookupnet(interface, &pNet, &pMask, errbuf) == -1)
	{
		sprintf(temp, "Fetching the network address & mask has failed: %s\n", errbuf);
		exit_with_message(temp, -1);
	}

	pcap_t *sniffer = pcap_open_live(interface, BUFSIZ, 0, 1000, errbuf);
	if(sniffer == NULL)
	{
		sprintf(temp, "pcap_open_live() failed: %s\n", errbuf);
		exit_with_message(temp, -1);
	}

	char filter[100] = "";
	create_filter(filter, port, arp, icmp, tcp, udp);
	//source: https://www.tcpdump.org/manpages/pcap_compile.3pcap.html
	if(pcap_compile(sniffer, &fp, filter, 0, pNet) == -1)
	{
		sprintf(temp, "pcap_compile() failed: %s\n", pcap_geterr(sniffer));
		exit_with_message(temp, -1);
	}

	if(pcap_setfilter(sniffer, &fp) == -1)
	{
		sprintf(temp, "pcap_setfilter() failed: %s\n", pcap_geterr(sniffer));
		exit_with_message(temp, -1);
	}

	pcap_loop(sniffer, pnum, callback, NULL);
	pcap_close(sniffer);

	return 0;
}
