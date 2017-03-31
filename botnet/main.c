#define WIN32
#define CURL_STATICLIB 
#define  HAVE_REMOTE
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "pcap.h"
#include <WinInet.h>
#include <Windows.h>
#include <WinSock2.h>
#include <string.h>
#include "pkt.h"
#include "p2f.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
static struct flow_record *process_tcp(const struct pcap_pkthdr *h, const u_char *tcp_start, int tcp_len, struct flow_key *key, struct packet_data *save_data);
static struct flow_record *process_udp(const struct pcap_pkthdr *h, const u_char *udp_start, int udp_len, struct flow_key *key, struct packet_data *save_data);
void print_hex_ascii_line(const unsigned char *data, int len, int offset);
static void print_payload(const unsigned char *payload, int len);
void check_table();
void create_packet(struct packet_data *save_data, int udp);
int create_session();
void update_session(struct flow_record *flow);

int number = 0;
struct flow_record *record_root; //记录flow流的起始节点
char ip_string[100] = "";

#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
char* time2char(struct timeval x)
{
	char tt[20] = "";
	char tmp[20] = "";
	strcat(tt, _itoa(x.tv_sec, tmp, 10));
	strcat(tt, ".");
	strcat(tt, _itoa(x.tv_usec, tmp, 10));
	return tt;
}
char* caltime(struct timeval start, struct timeval end)
{
	char res[20] = "";
	struct timeval tmp;
	if (start.tv_usec > end.tv_usec)
	{
		tmp.tv_sec = end.tv_sec - start.tv_sec;
		tmp.tv_usec = 1000000 + end.tv_usec - start.tv_usec;
	}
	else
	{
		tmp.tv_sec = end.tv_sec - start.tv_sec;
		tmp.tv_usec = end.tv_usec - start.tv_usec;
	}
	return time2char(tmp);
}
int main(int argc, char **argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_dumper_t *dumpfile;
	record_root = malloc(sizeof(struct flow_record));
	record_root->next = NULL;

	printf("请输入当前设备的ip地址，务必输入正确！\n");
	scanf("%s", ip_string);
	printf("请选择处理模式：\n1、在线抓包处理 \n2、处理离线pcap文件\n");
	int mode = 1;
	scanf("%d", &mode);
	if (mode == 1)
	{
		/* Retrieve the device list on the local machine */
		if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
		{
			fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
			exit(1);
		}

		/* Print the list */
		for (d = alldevs; d; d = d->next)
		{
			printf("%d. %s", ++i, d->name);
			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}

		if (i == 0)
		{
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			return -1;
		}

		printf("Enter the interface number (1-%d):", i);
		scanf_s("%d", &inum);

		if (inum < 1 || inum > i)
		{
			printf("\nInterface number out of range.\n");
			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}

		/* Jump to the selected adapter */
		for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);


		/* Open the adapter */
		if ((adhandle = pcap_open_live(d->name,	// name of the device
			65536,			// portion of the packet to capture. 
			// 65536 grants that the whole packet will be captured on all the MACs.
			1,				// promiscuous mode (nonzero means promiscuous)
			1000,			// read timeout
			errbuf			// error buffer
			)) == NULL)
		{
			fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}

		printf("\nlistening on %s... Press Ctrl+C to stop...\n", d->description);

		/* At this point, we no longer need the device list. Free it */
		pcap_freealldevs(alldevs);
	}
	else {
		printf("请输入所要进行处理的pcap文件名：");
		char filename[100] = "";
		memset(filename, 0, sizeof(filename));
		scanf("%s", filename);
		adhandle = pcap_open_offline(filename,errbuf);
		if (adhandle == NULL) {
			printf("Couldn't open pcap file %s: %s\n", filename, errbuf);
			return -1;
		}
	}
	

	check_table(); 

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	const struct ip_hdr *ip;
	unsigned int transport_len;
	unsigned int ip_hdr_len;
	const u_char *transport_start;
	struct flow_key key;
	unsigned char proto = 0;
	struct flow_record *record;
	struct packet_data save_data;
	save_data.da = malloc(sizeof(char) * 20);
	memset(save_data.da, 0, 20);
	save_data.sa = malloc(sizeof(char) * 20);
	memset(save_data.sa, 0, 20);
	/*获取当前时间戳*/
	save_data.time = header->ts;


	ip = (struct ip_hdr*)(pkt_data + ETHERNET_HDR_LEN);//获取头部信息
	ip_hdr_len = ip_hdr_length(ip);//头部长度
	if (ip_hdr_len < 20) {
		return;
	}
	if (ntohs(ip->ip_len) < sizeof(struct ip_hdr) || ntohs(ip->ip_len) > header->caplen) {
		/*
		* IP packet is malformed (shorter than a complete IP header, or
		* claims to be longer than it is), or not entirely captured by
		* libpcap (which will depend on MTU and SNAPLEN; you can change
		* the latter if need be).
		*/
		return;
	}
	transport_len = ntohs(ip->ip_len) - ip_hdr_len;
	char sendBuf[256];
	/* print source and destination IP addresses 
	printf("       from: %s\n", inet_ntoa(ip->ip_src));
	printf("         to: %s\n", inet_ntoa(ip->ip_dst));
	printf("     ip len: %u\n", ntohs(ip->ip_len));
	printf(" ip hdr len: %u\n", ip_hdr_len);*/
	if ((strcmp(inet_ntoa(ip->ip_src), "112.74.63.70") == 0) || strcmp(inet_ntoa(ip->ip_dst), "112.74.63.70") == 0) {
		return;
	}
	strcpy(save_data.sa, inet_ntoa(ip->ip_src));
	strcpy(save_data.da, inet_ntoa(ip->ip_dst));
	save_data.ip_len = ntohs(ip->ip_len);
	save_data.ip_hdr_len = ip_hdr_len;
	
	if (ip_fragment_offset(ip) == 0) {

		/* fill out IP-specific fields of flow key, plus proto selector */
		key.sa = ip->ip_src;
		key.da = ip->ip_dst;
		proto = key.prot = ip->ip_prot;

	}
	else {
		// printf("found IP fragment (offset: %02x)\n", ip_fragment_offset(ip));

		/*
		* select IP processing, since we don't have a TCP or UDP header
		*/
		key.sa = ip->ip_src;
		key.da = ip->ip_dst;
		proto = key.prot = IPPROTO_IP;
	}
	save_data.proto = proto;

	transport_start = pkt_data + (ETHERNET_HDR_LEN + ip_hdr_len);
	switch (proto) {
	case IPPROTO_TCP:
		record = process_tcp(header, transport_start, transport_len, &key, &save_data);
		//if (record) {
		//	update_all_tcp_features(tcp_feature_list);
		//}
		break;
	case IPPROTO_UDP:
		record = process_udp(header, transport_start, transport_len, &key, &save_data);
		break;
	/*case IPPROTO_ICMP:
		record = process_icmp(header, transport_start, transport_len, &key);
		break;
	case IPPROTO_IP:*/
	default:
		//record = process_ip(header, transport_start, transport_len, &key);
		break;
	}
}
static struct flow_record *process_tcp(const struct pcap_pkthdr *h, const u_char *tcp_start, int tcp_len, struct flow_key *key, struct packet_data *save_data)
{
	unsigned int tcp_hdr_len;//tcp头长度
	const unsigned char *payload; //payload
	unsigned int size_payload; //payload长度
	const struct tcp_hdr *tcp = (const struct tcp_hdr *)tcp_start; //tcp数据包开始的部分
	struct flow_record *record = NULL; //所属流的指针
	unsigned int cur_itr = 0;
	int create_flag = 0;//如果该数据包是syn则需要创建一个新的flow_record

	tcp_hdr_len = tcp_hdr_length(tcp);
	save_data->tcp_len = tcp_len;
	save_data->tcp_hdr_len = tcp_hdr_len;
	if (tcp_hdr_len < 20 || tcp_hdr_len > tcp_len) { //错误的数据包
		//printf("   * Invalid TCP header length: %u bytes\n", tcp_hdr_len);
		return NULL;
	}
	payload = tcp_start + tcp_hdr_len;
	size_payload = tcp_len - tcp_hdr_len;

	save_data->payload_size = size_payload;
	save_data->payload = payload;
	/*
	printf("   src port: %d\n", ntohs(tcp->src_port));
	printf( "   dst port: %d\n", ntohs(tcp->dst_port));
	printf("payload len: %u\n", size_payload);
	printf("    tcp len: %u\n", tcp_len);
	printf("tcp hdr len: %u\n", tcp_hdr_len);
	printf("      flags:");
	if (tcp->tcp_flags & TCP_FIN) { printf("FIN "); }
	if (tcp->tcp_flags & TCP_SYN) { printf("SYN "); }
	if (tcp->tcp_flags & TCP_RST) { printf("RST "); }
	if (tcp->tcp_flags & TCP_PSH) { printf("PSH "); }
	if (tcp->tcp_flags & TCP_ACK) { printf("ACK "); }
	if (tcp->tcp_flags & TCP_URG) { printf("URG "); }
	if (tcp->tcp_flags & TCP_ECE) { printf("ECE "); }
	if (tcp->tcp_flags & TCP_CWR) { printf("CWR "); }
	printf("\n");*/
	save_data->flag = 0;
	save_data->flag = (int)tcp->tcp_flags;
	if ((tcp->tcp_flags & 0xFD) == 0) { //只有SYN时 新建流
		create_flag = 1;
	}
	if (size_payload > 0) {
		//printf("    payload:\n");
		//print_payload(payload, size_payload);
	}

	key->sp = ntohs(tcp->src_port);
	key->dp = ntohs(tcp->dst_port);
	save_data->sp = key->sp;
	save_data->dp = key->dp;
	record = flow_key_get_record(key, record_root);//寻找是否有该数据包是否是已经存在的流的
	if (record == NULL) {
		record = create_new_records(key, record_root); //创建新的流
		record->start = save_data->time;
		record->end = save_data->time;
		record->np = 1;
		record->num_bytes = save_data->ip_len;
		record->nps = 1;
		record->nbs = save_data->ip_len;
	}
	else if (create_flag == 1){ //为syn时删除旧流穿件新流
		delete_record(record, record_root);
		record = create_new_records(key, record_root);
		record->start = save_data->time;
		record->end = save_data->time;
		record->np = 1;
		record->num_bytes = save_data->ip_len;
		record->nps = 1;
		record->nbs = save_data->ip_len;
	}
	else{
		record->end = save_data->time;
		record->np++;
		record->num_bytes += save_data->ip_len;
		if (record->key.sa.s_addr == key->sa.s_addr)
		{
			record->nps += 1;
			record->nbs += save_data->ip_len;
		}
		else
		{
			record->npr += 1;
			record->nbr += save_data->ip_len;
		}
	}

	//FILE *fp = fopen("res.txt", "a+");
	//printf("sa:%s\nda:%s\nsp:%d\ndp:%d\nproto:%d\nip_len:%d\nip_hdr_len:%d\ntcp_len:%d\ntcp_hdr_len:%d\nflag:%d\npayload_size:%d\npayload:%s\n\n", save_data->sa, save_data->da, save_data->sp, save_data->dp, save_data->proto, save_data->ip_len, save_data->ip_hdr_len, save_data->tcp_len, save_data->tcp_hdr_len, save_data->flag, save_data->payload_size, save_data->payload);
	//fclose(fp);
	char http_code[3] = "";
	save_data->http_status_code = 0;
	if (save_data->payload[0] == 'H' && save_data->payload[1] == 'T' &&save_data->payload[2] == 'T' &&save_data->payload[3] == 'P') {
		int i = 0;
		for (i = 0; i < 10; i++)
		{
			if (save_data->payload[i] == ' ')
			{
				http_code[0] = save_data->payload[i + 1];
				http_code[1] = save_data->payload[i + 2];
				http_code[2] = save_data->payload[i + 3];
				break;
			}
		}
		save_data->http_status_code = atoi(http_code);
	}
	save_data->flow = record->id;
	create_packet(save_data, 0);
	update_session(record);
	return record;
}

static void print_payload(const unsigned char *payload, int len) {
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;		        /* zero-based offset counter */
	const unsigned char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for (;;) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

void print_hex_ascii_line(const unsigned char *data, int len, int offset) {
	const unsigned char *d;
	int i, j;

	printf("%05d   ", offset);
	d = data;
	for (i = 0; i < len; i++) {
		printf("%02x ", *d);
		d++;
		if (i == 7)
			printf(" ");
	}
	if (len < 8)
		printf(" ");

	if (len < 16) {
		j = 16 - len;
		for (i = 0; i < j; i++) {
			printf("   ");
		}
	}
	printf("   ");

	d = data;
	for (i = 0; i < len; i++) {
		if (isprint(*d))
			printf("%c", *d);
		else
			printf(".");
		d++;
	}
	printf("\n");

	return;
}

void check_table() {
	
	char url[200] = "/bishe/check_table.php?tablename=";
	strcat(url, ip_string);
	HINTERNET hInternet = InternetOpen("Testing", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0); //初始化WinINet
	HINTERNET hConnect = InternetConnect(hInternet, "112.74.63.70", INTERNET_DEFAULT_HTTP_PORT,
		NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0); //连接服务器
	HINTERNET hOpenRequest = HttpOpenRequest(hConnect, "GET", url, HTTP_VERSION, NULL,
		0, INTERNET_FLAG_DONT_CACHE, 1); //创建http请求
	BOOL bRequest = HttpSendRequest(hOpenRequest, NULL, 0, NULL, 0); //发送http请求
	InternetCloseHandle(hInternet);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hOpenRequest);
}

void create_packet(struct packet_data *save_data, int udp)
{
	char options[655350] = "tablename=";
	char num[50];
	int i = 0;
	strcat(options, ip_string);
	if (udp == 1){
		strcat(options, "&udp=1");
	}
	else {
		strcat(options, "&udp=0");
	}
	strcat(options, "&sa=");
	strcat(options, save_data->sa);
	strcat(options, "&da=");
	strcat(options, save_data->da);
	strcat(options, "&sp=");
	strcat(options, _itoa(save_data->sp, num, 10));
	strcat(options, "&dp="); 
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(save_data->dp, num, 10));
	strcat(options, "&proto=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(save_data->proto, num, 10));
	strcat(options, "&ip_len=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(save_data->ip_len, num, 10));
	strcat(options, "&ip_hdr_len=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(save_data->ip_hdr_len, num, 10));
	strcat(options, "&tcp_len=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(save_data->tcp_len, num, 10));
	strcat(options, "&tcp_hdr_len=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(save_data->tcp_hdr_len, num, 10));
	strcat(options, "&flag=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(save_data->flag, num, 10));
	strcat(options, "&payload_size=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(save_data->payload_size, num, 10));
	strcat(options, "&time=");
	memset(num, 0, sizeof(num));
	strcat(options, time2char(save_data->time));
	strcat(options, "&http_status_code=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(save_data->http_status_code, num, 10));
	strcat(options, "&session=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(save_data->flow, num, 10));
	strcat(options, "&payload=");
	char tmp[5];
	for (i = 0; i < save_data->payload_size; i++)
	{
		memset(tmp, 0, sizeof(tmp));
		strcat(options, _itoa((int)save_data->payload[i], tmp, 16));
		strcat(options, " ");
	}
	//strcat(options, save_data->payload);
	//printf("%s", options);
	
	HINTERNET hInternet = InternetOpen("Testing", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0); //初始化WinINet
	char strSever[] = "112.74.63.70";
	HINTERNET hConnect = InternetConnect(hInternet, strSever, INTERNET_DEFAULT_HTTP_PORT,
		NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0); //连接服务器
	char strObject[] = "/bishe/create_packet.php";
	HINTERNET hOpenRequest = HttpOpenRequest(hConnect, "POST", strObject, HTTP_VERSION, NULL,
		0, INTERNET_FLAG_DONT_CACHE, 1); //创建http请求
	char hdrs[] = "Content-Type: application/x-www-form-urlencoded";
	BOOL bRequest = HttpSendRequest(hOpenRequest, hdrs, (DWORD)strlen(hdrs), options, (DWORD)strlen(options)); //发送http请求
	InternetCloseHandle(hInternet);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hOpenRequest);
}

int create_session() {
	int num;
	char url[200] = "/bishe/create_session.php?tablename=";
	strcat(url, ip_string);
	HINTERNET hInternet = InternetOpen("Testing", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0); //初始化WinINet
	HINTERNET hConnect = InternetConnect(hInternet, "112.74.63.70", INTERNET_DEFAULT_HTTP_PORT,
		NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0); //连接服务器
	HINTERNET hOpenRequest = HttpOpenRequest(hConnect, "GET", url, HTTP_VERSION, NULL,
		0, INTERNET_FLAG_DONT_CACHE, 1); //创建http请求
	BOOL bRequest = HttpSendRequest(hOpenRequest, NULL, 0, NULL, 0); //发送http请求
	char szBuffer[1024] = { 0 };
	DWORD dwByteRead = 0;
	while (InternetReadFile(hOpenRequest, szBuffer, sizeof(szBuffer), &dwByteRead) && dwByteRead > 0)
	{
	}
	num = atoi(szBuffer);
	InternetCloseHandle(hInternet);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hOpenRequest);
	return num;
}

void update_session(struct flow_record *flow)
{
	char options[655350] = "tablename=";
	char num[50];
	strcat(options, ip_string);
	strcat(options, "&id=");
	strcat(options, _itoa(flow->id, num, 10));
	strcat(options, "&sa=");
	strcat(options, inet_ntoa(flow->key.sa));
	strcat(options, "&da=");
	strcat(options, inet_ntoa(flow->key.da));
	strcat(options, "&sp=");
	strcat(options, _itoa(flow->key.sp, num, 10));
	strcat(options, "&dp=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(flow->key.dp, num, 10));
	strcat(options, "&time=");
	memset(num, 0, sizeof(num));
	strcat(options, time2char(flow->start));
	strcat(options, "&duration=");
	memset(num, 0, sizeof(num));
	strcat(options, caltime(flow->start, flow->end));
	strcat(options, "&np=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(flow->np, num, 10));
	strcat(options, "&nb=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(flow->num_bytes, num, 10));
	strcat(options, "&nbr=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(flow->nbr, num, 10));
	strcat(options, "&nbs=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(flow->nbs, num, 10));
	strcat(options, "&npr=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(flow->npr, num, 10));
	strcat(options, "&nps=");
	memset(num, 0, sizeof(num));
	strcat(options, _itoa(flow->nps, num, 10));
	//printf("%s", options);

	HINTERNET hInternet = InternetOpen("Testing", INTERNET_OPEN_TYPE_DIRECT, "http=", NULL, 0); //初始化WinINet
	char strSever[] = "112.74.63.70";
	HINTERNET hConnect = InternetConnect(hInternet, strSever, INTERNET_DEFAULT_HTTP_PORT,
		NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0); //连接服务器
	char strObject[] = "/bishe/update_session.php";
	HINTERNET hOpenRequest = HttpOpenRequest(hConnect, "POST", strObject, HTTP_VERSION, NULL,
	0, INTERNET_FLAG_DONT_CACHE, 1); //创建http请求
	char hdrs[] = "Content-Type: application/x-www-form-urlencoded";
	BOOL bRequest = HttpSendRequest(hOpenRequest, hdrs, (DWORD)strlen(hdrs), options, (DWORD)strlen(options)); //发送http请求
	InternetCloseHandle(hInternet);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hOpenRequest);
}

static struct flow_record *process_udp(const struct pcap_pkthdr *h, const u_char *udp_start, int udp_len, struct flow_key *key, struct packet_data *save_data) {
	unsigned int udp_hdr_len;
	const unsigned char *payload;
	unsigned int size_payload;
	const struct udp_hdr *udp = (const struct udp_hdr *)udp_start;
	struct flow_record *record = NULL;

	udp_hdr_len = 8;
	if (udp_len < 8) {
		// fprintf(info, "   * Invalid UDP packet length: %u bytes\n", udp_len);
		return NULL;
	}
	//这里的tcp其实是udp
	save_data->tcp_len = udp_len;
	save_data->tcp_hdr_len = udp_hdr_len;

	payload = (udp_start + udp_hdr_len);
	size_payload = udp_len - udp_hdr_len;

	save_data->payload_size = size_payload;
	save_data->payload = payload;

	save_data->flag = -1;
	/*
	* Print payload data; it might be binary, so don't just
	* treat it as a string.
	*/
	key->sp = ntohs(udp->src_port);
	key->dp = ntohs(udp->dst_port);
	save_data->sp = key->sp;
	save_data->dp = key->dp;
	save_data->http_status_code = 0;
	save_data->flow = -1;
	create_packet(save_data,1);
	return record;
}
