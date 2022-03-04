
#include<stdio.h>
#include<malloc.h>
#include<string.h>
#include<errno.h>
#include<signal.h>
#include<stdbool.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<sys/ioctl.h>

#include<linux/if_packet.h>
#include<netinet/in.h>	
#include<net/if.h>	 
#include<netinet/if_ether.h>    // for ethernet header
#include<netinet/ip.h>		// for ip header
#include<netinet/udp.h>		// for udp header
#include<netinet/tcp.h>
#include<arpa/inet.h>           // to avoid warning at inet_ntoa

#define destination_ip 255.255.255.255

FILE* log_txt;
int total,tcp,udp,icmp,igmp,other,iphdrlen, flag = 0;

struct sockaddr saddr;
struct sockaddr_in source,dest;

 unsigned char DESTMAC0,DESTMAC1,DESTMAC2,DESTMAC3,DESTMAC4,DESTMAC5;
 unsigned char trans_id[4];

int request_flag = 0;

//======================Sender===============================================
struct ifreq ifreq_c,ifreq_i,ifreq_ip; /// for each ioctl keep diffrent ifreq structure otherwise error may come in sending(sendto )
unsigned char *sendbuff;
int total_len=0,send_len;
int sock_raw;
unsigned char my_ip[4];

void get_eth_index()
{
	memset(&ifreq_i,0,sizeof(ifreq_i));
	strncpy(ifreq_i.ifr_name,"wlan0",IFNAMSIZ-1);

	if((ioctl(sock_raw,SIOCGIFINDEX,&ifreq_i))<0)
		printf("error in index ioctl reading");

	printf("index=%d\n",ifreq_i.ifr_ifindex);

}

void get_mac()
{
	memset(&ifreq_c,0,sizeof(ifreq_c));
	strncpy(ifreq_c.ifr_name,"wlan0",IFNAMSIZ-1);

	if((ioctl(sock_raw,SIOCGIFHWADDR,&ifreq_c))<0)
		printf("error in SIOCGIFHWADDR ioctl reading");

	printf("Mac= %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]));

	
	printf("ethernet packaging start ... \n");
	
	struct ethhdr *eth = (struct ethhdr *)(sendbuff);
  	eth->h_source[0] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]);
  	eth->h_source[1] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]);
   	eth->h_source[2] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]);
   	eth->h_source[3] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]);
   	eth->h_source[4] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]);
   	eth->h_source[5] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]);

   	eth->h_dest[0]    =  DESTMAC0;
   	eth->h_dest[1]    =  DESTMAC1;
   	eth->h_dest[2]    =  DESTMAC2;
  	eth->h_dest[3]    =  DESTMAC3;
   	eth->h_dest[4]    =  DESTMAC4;
   	eth->h_dest[5]    =  DESTMAC5;

   	eth->h_proto = htons(ETH_P_IP);   //0x800

   	printf("ethernet packaging done.\n");

	total_len+=sizeof(struct ethhdr);


}

void get_data()
{
	int i =0;	
	sendbuff[total_len++]	=	0x02;
	sendbuff[total_len++]	=	0x01;
	sendbuff[total_len++]	=	0x06;
	sendbuff[total_len++]	=	0x00;
	for(i=0;i<4;i++)
		sendbuff[total_len++] = trans_id[i];
	
	for(i=0 ; i<8;i++)	
		sendbuff[total_len++]	=	0x00;
	
	sendbuff[total_len++]	=	0xc0;
	sendbuff[total_len++]	=	0xa8;
	sendbuff[total_len++]	=	0x00;
	sendbuff[total_len++]	=	0x78;

// need to add server ip
	sendbuff[total_len++]	=	0xc0;
	sendbuff[total_len++]	=	0xa8;
	sendbuff[total_len++]	=	0x00;
	sendbuff[total_len++]	=	0x6c;
	
	for(i=0 ; i<4;i++)	
		sendbuff[total_len++]	=	0x00;
	
//Mac address
	sendbuff[total_len++]	=	DESTMAC0;
	sendbuff[total_len++]	=	DESTMAC1;
	sendbuff[total_len++]	=	DESTMAC2;
	sendbuff[total_len++]	=	DESTMAC3;
	sendbuff[total_len++]	=	DESTMAC4;
	sendbuff[total_len++]	=	DESTMAC5;
	
	for(i=0 ; i<(74+128);i++)	
		sendbuff[total_len++]	=	0x00;
	
//magic cookie
	sendbuff[total_len++]	=	0x63;
	sendbuff[total_len++]	=	0x82;
	sendbuff[total_len++]	=	0x53;
	sendbuff[total_len++]	=	0x63;
	
	sendbuff[total_len++]	=	0x35;
	sendbuff[total_len++]	=	0x01;
	sendbuff[total_len++]	=	0x02;
//subnet musk
	sendbuff[total_len++]	=	0x01;
	sendbuff[total_len++]	=	0x04;
	sendbuff[total_len++]	=	0xff;
	sendbuff[total_len++]	=	0xff;
	sendbuff[total_len++]	=	0xff;
	sendbuff[total_len++]	=	0x00;

//renewal time 
	sendbuff[total_len++]	=	0x3a;
	sendbuff[total_len++]	=	0x04;
	sendbuff[total_len++]	=	0x00;
	sendbuff[total_len++]	=	0x00;
	sendbuff[total_len++]	=	0x07;
	sendbuff[total_len++]	=	0x08;	
//rebinding time value
	sendbuff[total_len++]	=	0x3b;
	sendbuff[total_len++]	=	0x04;
	sendbuff[total_len++]	=	0x00;
	sendbuff[total_len++]	=	0x00;
	sendbuff[total_len++]	=	0x0c;
	sendbuff[total_len++]	=	0x4e;
//ip lease time
	sendbuff[total_len++]	=	0x33;
	sendbuff[total_len++]	=	0x04;
	sendbuff[total_len++]	=	0x00;
	sendbuff[total_len++]	=	0x00;
	sendbuff[total_len++]	=	0x0e;
	sendbuff[total_len++]	=	0x10;
//dhcp server identifier
	sendbuff[total_len++]	=	0x36;
	sendbuff[total_len++]	=	0x04;
	sendbuff[total_len++]	=	0xc0;
	sendbuff[total_len++]	=	0xa8;
	sendbuff[total_len++]	=	0x00;
	sendbuff[total_len++]	=	0x6c;	
//Option end	
	sendbuff[total_len++]	=	0xff;

//padding
	for(i=0 ; i<(32);i++)	
		sendbuff[total_len++]	=	0x00;


}

void get_udp()
{
	struct udphdr *uh = (struct udphdr *)(sendbuff + sizeof(struct iphdr) + sizeof(struct ethhdr));

	uh->source	= htons(23451);
	uh->dest	= htons(23452);
	uh->check	= 0;

	total_len+= sizeof(struct udphdr);
	get_data();
	uh->len		= htons((total_len - sizeof(struct iphdr) - sizeof(struct ethhdr)));

}

unsigned short checksum(unsigned short* buff, int _16bitword)
{
	unsigned long sum;
	for(sum=0;_16bitword>0;_16bitword--)
		sum+=htons(*(buff)++);
	do
	{
		sum = ((sum >> 16) + (sum & 0xFFFF));
	}
	while(sum & 0xFFFF0000);

	return (~sum);


	
}

void get_ip()
{
	memset(&ifreq_ip,0,sizeof(ifreq_ip));
	strncpy(ifreq_ip.ifr_name,"wlan0",IFNAMSIZ-1);
  	 if(ioctl(sock_raw,SIOCGIFADDR,&ifreq_ip)<0)
 	 {
		printf("error in SIOCGIFADDR \n");
	 }
	
	printf("%s\n",inet_ntoa((((struct sockaddr_in*)&(ifreq_ip.ifr_addr))->sin_addr)));
//	 inet_ntoa((((struct sockaddr_in*)&(ifreq_ip.ifr_addr))->sin_addr));

/****** OR
	int i;
	for(i=0;i<14;i++)
	printf("%d\n",(unsigned char)ifreq_ip.ifr_addr.sa_data[i]); ******/

	struct iphdr *iph = (struct iphdr*)(sendbuff + sizeof(struct ethhdr));
	iph->ihl	= 5;
	iph->version	= 4;
	iph->tos	= 16;
	iph->id		= htons(10201);
	iph->ttl	= 64;
	iph->protocol	= 17;
	iph->saddr	= inet_addr(inet_ntoa((((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr)));
	iph->daddr	= inet_addr("destination_ip"); // destination IP address
	total_len += sizeof(struct iphdr); 
	get_udp();

	iph->tot_len	= htons(total_len - sizeof(struct ethhdr));
	iph->check	= htons(checksum((unsigned short*)(sendbuff + sizeof(struct ethhdr)), (sizeof(struct iphdr)/2)));






}

void send_data()
{
	sock_raw=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW);
	if(sock_raw == -1)
		printf("error in socket");

	sendbuff=(unsigned char*)malloc(512); 
	memset(sendbuff,0,512);


	get_eth_index();  // interface number
	get_mac();
	get_ip();

	struct sockaddr_ll sadr_ll;
	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex;
	sadr_ll.sll_halen   = ETH_ALEN;
	sadr_ll.sll_addr[0]  = DESTMAC0;
	sadr_ll.sll_addr[1]  = DESTMAC1;
	sadr_ll.sll_addr[2]  = DESTMAC2;
	sadr_ll.sll_addr[3]  = DESTMAC3;
	sadr_ll.sll_addr[4]  = DESTMAC4;
	sadr_ll.sll_addr[5]  = DESTMAC5;

	printf("sending...\n");
	while(1)
	{
	send_len = sendto(sock_raw,sendbuff,512,0,(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
		if(send_len<0)
		{
			printf("error in sending....sendlen=%d....errno=%d\n",send_len,errno);
			break;

		}

	}
	

}



//======================Sniffer==============================================
void ethernet_header(unsigned char* buffer,int buflen)
{
	struct ethhdr *eth = (struct ethhdr *)(buffer);
	fprintf(log_txt,"\nEthernet Header\n");
	fprintf(log_txt,"\t|-Source Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
	fprintf(log_txt,"\t|-Destination Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
	fprintf(log_txt,"\t|-Protocol		: %d\n",eth->h_proto);


	DESTMAC0	= eth->h_source[0];
   	DESTMAC1	= eth->h_source[1];
   	DESTMAC2	= eth->h_source[2];
	DESTMAC3	= eth->h_source[3];
	DESTMAC4	= eth->h_source[4];
	DESTMAC5	= eth->h_source[5];
fprintf(log_txt,"\t|-MAC saved Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",DESTMAC0,DESTMAC1,DESTMAC2,DESTMAC3,DESTMAC4,DESTMAC5);

}

void ip_header(unsigned char* buffer,int buflen)
{
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	iphdrlen =ip->ihl*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;     
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;     

	fprintf(log_txt , "\nIP Header\n");

	fprintf(log_txt , "\t|-Version              : %d\n",(unsigned int)ip->version);
	fprintf(log_txt , "\t|-Internet Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
	fprintf(log_txt , "\t|-Type Of Service   : %d\n",(unsigned int)ip->tos);
	fprintf(log_txt , "\t|-Total Length      : %d  Bytes\n",ntohs(ip->tot_len));
	fprintf(log_txt , "\t|-Identification    : %d\n",ntohs(ip->id));
	fprintf(log_txt , "\t|-Time To Live	    : %d\n",(unsigned int)ip->ttl);
	fprintf(log_txt , "\t|-Protocol 	    : %d\n",(unsigned int)ip->protocol);
	fprintf(log_txt , "\t|-Header Checksum   : %d\n",ntohs(ip->check));
	fprintf(log_txt , "\t|-Source IP         : %s\n", inet_ntoa(source.sin_addr));
	fprintf(log_txt , "\t|-Destination IP    : %s\n",inet_ntoa(dest.sin_addr));

		

	
}

void payload(unsigned char* buffer,int buflen)
{
	int i=0;
	unsigned char * data = (buffer + iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr));
	fprintf(log_txt,"\nData\n");
	int remaining_data = buflen - (iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr));
	for(i=0;i<remaining_data;i++)
	{
		if(i!=0 && i%16==0)
			fprintf(log_txt,"\n");
		if(i>3 && i<8)
			trans_id[i-4] = data[i];
		fprintf(log_txt," %.2X ",data[i]);
	}
	
	if(request_flag == 1){
		send_data();
		request_flag = 0;
	}
	//	fprintf(log_txt,"check %.2X %.2X %.2X %.2X",trans_id[0],trans_id[1],trans_id[2],trans_id[3]);
	fprintf(log_txt,"\n");



}

void tcp_header(unsigned char* buffer,int buflen)
{
	fprintf(log_txt,"\n*************************TCP Packet******************************");
   	ethernet_header(buffer,buflen);
  	ip_header(buffer,buflen);

   	struct tcphdr *tcp = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
   	fprintf(log_txt , "\nTCP Header\n");
   	fprintf(log_txt , "\t|-Source Port          : %u\n",ntohs(tcp->source));
   	fprintf(log_txt , "\t|-Destination Port     : %u\n",ntohs(tcp->dest));
   	fprintf(log_txt , "\t|-Sequence Number      : %u\n",ntohl(tcp->seq));
   	fprintf(log_txt , "\t|-Acknowledge Number   : %u\n",ntohl(tcp->ack_seq));
   	fprintf(log_txt , "\t|-Header Length        : %d DWORDS or %d BYTES\n" ,(unsigned int)tcp->doff,(unsigned int)tcp->doff*4);
	fprintf(log_txt , "\t|----------Flags-----------\n");
	fprintf(log_txt , "\t\t|-Urgent Flag          : %d\n",(unsigned int)tcp->urg);
	fprintf(log_txt , "\t\t|-Acknowledgement Flag : %d\n",(unsigned int)tcp->ack);
	fprintf(log_txt , "\t\t|-Push Flag            : %d\n",(unsigned int)tcp->psh);
	fprintf(log_txt , "\t\t|-Reset Flag           : %d\n",(unsigned int)tcp->rst);
	fprintf(log_txt , "\t\t|-Synchronise Flag     : %d\n",(unsigned int)tcp->syn);
	fprintf(log_txt , "\t\t|-Finish Flag          : %d\n",(unsigned int)tcp->fin);
	fprintf(log_txt , "\t|-Window size          : %d\n",ntohs(tcp->window));
	fprintf(log_txt , "\t|-Checksum             : %d\n",ntohs(tcp->check));
	fprintf(log_txt , "\t|-Urgent Pointer       : %d\n",tcp->urg_ptr);

	payload(buffer,buflen);

fprintf(log_txt,"*****************************************************************\n\n\n");
}

void udp_header(unsigned char* buffer, int buflen)
{
	fprintf(log_txt,"\n*************************UDP Packet******************************");
	ethernet_header(buffer,buflen);
	ip_header(buffer,buflen);
	fprintf(log_txt,"\nUDP Header\n");

	struct udphdr *udp = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	fprintf(log_txt , "\t|-Source Port    	: %d\n" , ntohs(udp->source));
	fprintf(log_txt , "\t|-Destination Port	: %d\n" , ntohs(udp->dest));
	fprintf(log_txt , "\t|-UDP Length      	: %d\n" , ntohs(udp->len));
	fprintf(log_txt , "\t|-UDP Checksum   	: %d\n" , ntohs(udp->check));
	
	if(68 == ntohs(udp->source) && 67 == ntohs(udp->dest))
	{	fprintf(log_txt , "UDP request\n");
		request_flag = 1;
	}
	flag = 0;

	payload(buffer,buflen);

	fprintf(log_txt,"*****************************************************************\n\n\n");



}

void data_process(unsigned char* buffer,int buflen)
{
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof (struct ethhdr));
	++total;
	/* we will se UDP Protocol only*/ 
	switch (ip->protocol)    //see /etc/protocols file 
	{

		case 6:
			++tcp;
			//tcp_header(buffer,buflen);
			break;

		case 17:
			++udp;
			udp_header(buffer,buflen);
			break;

		default:
			++other;

	}
	printf("TCP: %d  UDP: %d  Other: %d  Toatl: %d  \r",tcp,udp,other,total);


}



int main()
{

	int sock_r,saddr_len,buflen;

	unsigned char* buffer = (unsigned char *)malloc(65536); 
	memset(buffer,0,65536);

	log_txt=fopen("log.txt","w");
	if(!log_txt)
	{
		printf("unable to open log.txt\n");
		return -1;

	}

	printf("starting .... \n");

	sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)); 
	if(sock_r<0)
	{
		printf("error in socket\n");
		return -1;
	}

	while(1)
	{
		saddr_len=sizeof saddr;
		buflen=recvfrom(sock_r,buffer,65536,0,&saddr,(socklen_t *)&saddr_len);


		if(buflen<0)
		{
			printf("error in reading recvfrom function\n");
			return -1;
		}
		fflush(log_txt);
		data_process(buffer,buflen);

	}

	close(sock_r);// use signals to close socket 
	printf("DONE!!!!\n");

}
