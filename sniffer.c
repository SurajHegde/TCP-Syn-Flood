#include<stdio.h> //For standard things
#include<stdlib.h> //malloc
#include<unistd.h>
#include<string.h> //memset
#include<netinet/ip_icmp.h> //Provides declarations for icmp header
#include<netinet/udp.h> //Provides declarations for udp header
#include<netinet/tcp.h> //Provides declarations for tcp header
#include<netinet/ip.h> //Provides declarations for ip header
#include<sys/socket.h>

#include<arpa/inet.h>
#include<netinet/in.h>
#include<time.h>
void ProcessPacket(unsigned char* , int);
int sock_raw;
int tcp=0,total=0,i,j;
struct sockaddr_in source,dest;

struct node {
  char ip[20];
  int count;
  struct node *next;
} *head;

clock_t t ;

void check_and_reset(struct node* head){
  if(!((clock() - t)/CLOCKS_PER_SEC)%5){
    struct node *temp = head ;
    while(temp){
      temp->count = 0 ;
      temp = temp->next ;
    }
  }
}

int main()
{
  int saddr_size , data_size;
  struct sockaddr saddr;
  struct in_addr in;
  clock_t t = clock();
  unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
  printf("Starting...\n");
  //Create a raw socket that shall sniff
  sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
  if(sock_raw < 0){
    printf("Socket Error\n");
    return 1;
  }
  while(1){
    saddr_size = sizeof saddr;
    //Receive a packet
    data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
    if(data_size <0 )
      {
	printf("Recvfrom error , failed to get packets\n");
	return 1;
      }
    //Now process the packet
    ProcessPacket(buffer , data_size);
  }
  close(sock_raw);
  printf("Finished");
  return 0;
}
void ProcessPacket(unsigned char* buffer, int size)
{
  //Get the IP Header part of this packet
  struct iphdr *iph = (struct iphdr*)buffer;
  ++total;
  //TCP Protocol
  ++tcp;
  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = iph->saddr;
  if(head == NULL){
    head = (struct node *)malloc(sizeof(struct node)) ;
    strcpy(head->ip, inet_ntoa(source.sin_addr)) ;
    head->count = 1 ;
    head->next = NULL ;
  }
  else{
    struct node *temp = head ;
    struct node *prev = NULL ;
    temp = head ;
    while(temp){
      if(!strcmp(temp->ip, inet_ntoa(source.sin_addr)))
	break ;
      prev = temp ;
      temp = temp->next ;
    }
    if(temp){
      temp->count++ ;
      if(temp->count > 4096){
	printf("Source IP Attacker : %s\n",inet_ntoa(source.sin_addr));
	char command[100];
	strcat(command,"sudo iptables -A INPUT -s ");
	strcat(command,inet_ntoa(source.sin_addr));
	strcat(command," -j DROP");
	system(command);
	exit(0);
      }
      if(prev)
	prev->next = temp->next ;
      temp->next = head ;
      head = temp ;
    }
    else{
      struct node *temp = (struct node *)malloc(sizeof(struct node)) ;
      strcpy(temp->ip, inet_ntoa(source.sin_addr)) ;
      temp->count = 1 ;
      temp->next = head ;
      head = temp ;
    }
  }
  printf("TCP : %d\r",tcp);
}
