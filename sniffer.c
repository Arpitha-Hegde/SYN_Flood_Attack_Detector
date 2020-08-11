/*
    Project: SYN Flood Attack Detector in C
*/
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
 
#include<unistd.h> //for sleep()
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for ICMP header
#include<netinet/udp.h>   //Provides declarations for UDP header
#include<netinet/tcp.h>   //Provides declarations for TCP header
#include<netinet/ip.h>    //Provides declarations for IP header

#include "connection.h" //implementation of custom defined doubly linked list functions
 
struct sockaddr_in source,dest;

int tcp = 0,udp = 0,icmp = 0,others = 0,igmp = 0,total = 0, warningNumber = 0,i,j; 

LIST_HEAD(connectionHead);

void printEthernetHeader(const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    printf( "\n");
    printf( "Ethernet Header\n");
    printf( "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf( "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf( "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}
 
void printIPHeader(const u_char * Buffer, int Size)
{
    printEthernetHeader(Buffer , Size);
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    printf( "\n");
    printf( "IP Header\n");
    printf( "   |-IP Version        : %d\n",(unsigned int)iph->version);
    printf( "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf( "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf( "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    printf( "   |-Identification    : %d\n",ntohs(iph->id));
    printf( "   |-TTL               : %d\n",(unsigned int)iph->ttl);
    printf( "   |-Protocol          : %d\n",(unsigned int)iph->protocol);
    printf( "   |-Checksum          : %d\n",ntohs(iph->check));
    printf( "   |-Source IP         : %s\n" , inet_ntoa(source.sin_addr) );
    printf( "   |-Destination IP    : %s\n" , inet_ntoa(dest.sin_addr) );
}
 
void processTCPPacket(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;

    char* sourceIP;
    char* destinationIP;
    uint16_t sourcePort,destinationPort;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    //int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    sourceIP = malloc(strlen(inet_ntoa(source.sin_addr))+1);
    strcpy(sourceIP,inet_ntoa(source.sin_addr));

    destinationIP = malloc(strlen(inet_ntoa(dest.sin_addr))+1); 
    strcpy(destinationIP,inet_ntoa(dest.sin_addr));

    sourcePort = ntohs(tcph->source);
    destinationPort = ntohs(tcph->dest);    
     
    
    printf( "\n\n***********************TCP Packet*************************\n");  
         
    printIPHeader(Buffer,Size);
         
    printf( "\n");
    printf( "TCP Header\n");
    printf( "   |-Source Port          : %u\n",ntohs(tcph->source));
    printf( "   |-Destination Port     : %u\n",ntohs(tcph->dest));
    printf( "   |-Sequence Number      : %u\n",ntohl(tcph->seq));
    printf( "   |-Acknowledge Number   : %u\n",ntohl(tcph->ack_seq));
    printf( "   |-Header Length        : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    printf( "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf( "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf( "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf( "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf( "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf( "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf( "   |-Window               : %d\n",ntohs(tcph->window));
    printf( "   |-Checksum             : %d\n",ntohs(tcph->check));
    printf( "   |-Urgent Pointer       : %d\n",tcph->urg_ptr);
    printf( "\n");

    /* checking for SYN FLOOD Attack*/

    /*
     *  1. Track TCP packets which have SYN flag or SYN-ACK flags set
     *  2. Create a doubly-linked list of unique connections which stores unique tuple of source IP address, 
     *     destination IP address, source port number and destination port number.
     *  3. Check in the list, if the packet is present.
     *     (NOTE: In case of TCP packet with SYN-ACK flags set, source IP address, destination IP address, 
     *      source port number and destination port number will be reversed.) 
     *  4. If TCP packet with SYN flag set is present in the list, then increment connectionRequests. 
     *  5. If TCP packet with SYN-ACK flags set is present in the list,then increment positiveResponses. 
     *  6. Add TCP packet to the connection list if not present already.
     *  7. Monitor the ratio of SYN-ACK:SYN. When the ratio crosses 3:1, print a warning message.
     */

    struct uniqueConnection* connectionNodePtr = NULL;

    if((unsigned int)tcph->syn == 1 && (unsigned int)tcph->ack == 1) //if SYN and ACK are set
    {
    	connectionNodePtr = checkList(destinationIP,sourceIP,destinationPort,sourcePort,&connectionHead);
    	
        if(connectionNodePtr != NULL)
    		connectionNodePtr->positiveResponses++; //simulating SYN-ACK packet
    }

    else if((unsigned int)tcph->syn == 1 && (unsigned int)tcph->ack == 0) //if SYN is set 
    {

    	connectionNodePtr = checkList(sourceIP,destinationIP,sourcePort,destinationPort,&connectionHead);

    	if(connectionNodePtr != NULL)
    		connectionNodePtr->connectionRequests++; //simulating SYN packet

    }

    if(connectionNodePtr == NULL)
    {
    	add_node(sourceIP,destinationIP,sourcePort,destinationPort,&connectionHead); //add connection 
    	return;
    }
    
    if((connectionNodePtr->positiveResponses - connectionNodePtr->connectionRequests) > 1 && connectionNodePtr->connectionRequests == 1)
	{

	    printf("\n***************************WARNING**********************\n");
	    printf("This frame is a suspected retransmission. Possible SYN FLOOD attack\n");
	    printf( "   |-Source IP          : %s\n" , sourceIP );
		printf( "   |-Target IP          : %s\n" , destinationIP);
        printf( "   |-Source Port        : %u\n" , sourcePort );
        printf( "   |-Target Port        : %u\n" , destinationPort );
		printf( "   |-Connection requests: %d\n" ,connectionNodePtr->connectionRequests);
		printf( "   |-Positive Responses : %d\n" ,connectionNodePtr->positiveResponses);
		printf( "   |-Frame Number       : %d\n" ,total);
        printf( "   |-Warning number     : %d\n" , warningNumber);
		sleep(10);
	}
       
    
                     
    printf( "\n###########################################################");

}

void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
     
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
            processTCPPacket(buffer , size);
            break;
         
        case 17: //UDP Protocol
            ++udp;
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    //printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}

 
int main(int argc, char **argv)
{
    pcap_t *handle; //Handle of the file that shall be sniffed
    char errbuf[100];
     
    // open capture file for offline processing
    printf("Opening the capture file for for sniffing .... \n");

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) 
    {
    fprintf (stderr, "%s: pcap_open_offline() failed: %s\n", argv[0], errbuf);
    exit(-1);
    }

    printf("File Opened!\n");
   
    // start packet processing loop, just like live capture
    if (pcap_loop(handle , 0 , processPacket , NULL) < 0)
    {
        fprintf (stderr, "%s: pcap_open_offline() failed: %s\n", argv[0], errbuf);
        exit(-1);
    }
    
    deleteAllConnections(&connectionHead);

    return 0;   
}