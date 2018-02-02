#include "stdafx.h"

#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <thread>

#include "Global.h"
#include "PacketHeader.h"
#include "utlist.h"
#include "pcap.h"

//#pragma comment(lib, "Packet.lib")
//#pragma comment(lib, "wpcap.lib")

typedef enum { PROTO_TCP, PROTO_UDP, PROTO_TCP6, PROTO_UDP6 } proto_t;

typedef struct node {
	DWORD port;
	proto_t proto;
	DWORD address;
	struct node * prev;
	struct node * next;
} node_t;

node_t *netGlobalList = NULL;

// Need to link with Iphlpapi.lib and Ws2_32.lib
//#pragma comment(lib, "iphlpapi.lib")
//#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
/* Note: could also use malloc() and free() */

int getTcpByPid(DWORD *pidList, DWORD pidCount, node_t **pList)
{

	// Declare and initialize variables
	PMIB_TCPTABLE2 pTcpTable;
	ULONG ulSize = 0;
	DWORD dwRetVal = 0;

	node_t *tmpList = NULL;
	node_t *el = NULL;

	char szLocalAddr[128];
	char szRemoteAddr[128];

	struct in_addr IpAddr;

	int i, j;

	pTcpTable = (MIB_TCPTABLE2 *)MALLOC(sizeof(MIB_TCPTABLE2));
	if (pTcpTable == NULL) {
		printf("Error allocating memory\n");
		return 1;
	}

	ulSize = sizeof(MIB_TCPTABLE);
	// Make an initial call to GetTcpTable2 to
	// get the necessary size into the ulSize variable
	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) ==
		ERROR_INSUFFICIENT_BUFFER) {
		FREE(pTcpTable);
		pTcpTable = (MIB_TCPTABLE2 *)MALLOC(ulSize);
		if (pTcpTable == NULL) {
			printf("Error allocating memory\n");
			return 1;
		}
	}
	// Make a second call to GetTcpTable2 to get
	// the actual data we require
	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) == NO_ERROR) {
		for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
			for (j = 0; j < pidCount; j++) {
				if (pTcpTable->table[i].dwOwningPid != pidList[j]) {
					continue;
				}
				int find = 0;
				DL_FOREACH(tmpList, el) {
					if (el->port == (u_short)pTcpTable->table[i].dwLocalPort) {
						find = 1;
						break;
					}
				}
				if (find) {
					continue;
				}

				node_t *item = NULL;
				while (!(item = (node_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(node_t))));
				item->port = (u_short)pTcpTable->table[i].dwLocalPort;
				item->address = (u_long)pTcpTable->table[i].dwLocalAddr;
				item->proto = PROTO_TCP;
				DL_APPEND(tmpList, item);

				IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
				strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));

				//printf("\n");
				//printf("\tTCP[%d] Local Addr: %s\n", i, szLocalAddr);
				//printf("\tTCP[%d] Local Port: %d \n", i,
				//	ntohs((u_short)pTcpTable->table[i].dwLocalPort));

				IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
				strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));
				//printf("\tTCP[%d] Remote Addr: %s\n", i, szRemoteAddr);
				//printf("\tTCP[%d] Remote Port: %d\n", i,
				//	ntohs((u_short)pTcpTable->table[i].dwRemotePort));

				//printf("\tTCP[%d] Owning PID: %d\n", i, pTcpTable->table[i].dwOwningPid);
			}
		}

		node_t *list = *pList;
		DL_CONCAT(list, tmpList);
		*pList = list;
	}
	else {
		printf("\tGetTcpTable2 failed with %d\n", dwRetVal);
		FREE(pTcpTable);
		return 1;
	}

	if (pTcpTable != NULL) {
		FREE(pTcpTable);
		pTcpTable = NULL;
	}

	return 0;
}

int getUdpByPid(DWORD *pidList, DWORD pidCount, node_t **pList)
{

	// Declare and initialize variables
	PMIB_UDPTABLE_OWNER_PID pUdpTable;
	ULONG ulSize = 0;
	DWORD dwRetVal = 0;

	node_t *tmpList = NULL;
	node_t *el = NULL;

	char szLocalAddr[128];

	struct in_addr IpAddr;

	int i, j;

	pUdpTable = (MIB_UDPTABLE_OWNER_PID *)MALLOC(sizeof(MIB_UDPTABLE_OWNER_PID));
	if (pUdpTable == NULL) {
		printf("Error allocating memory\n");
		return 1;
	}

	ulSize = sizeof(MIB_UDPTABLE_OWNER_PID);
	// Make an initial call to GetTcpTable2 to
	// get the necessary size into the ulSize variable
	if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &ulSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)) ==
		ERROR_INSUFFICIENT_BUFFER) {
		FREE(pUdpTable);
		pUdpTable = (MIB_UDPTABLE_OWNER_PID *)MALLOC(ulSize);
		if (pUdpTable == NULL) {
			printf("Error allocating memory\n");
			return 1;
		}
	}
	// Make a second call to GetTcpTable2 to get
	// the actual data we require
	if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &ulSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)) == NO_ERROR) {
		for (i = 0; i < (int)pUdpTable->dwNumEntries; i++) {
			for (j = 0; j < pidCount; j++) {
				if (pUdpTable->table[i].dwOwningPid != pidList[j]) {
					continue;
				}
				int find = 0;
				DL_FOREACH(tmpList, el) {
					if (el->port == (u_short)pUdpTable->table[i].dwLocalPort) {
						find = 1;
						break;
					}
				}
				if (find) {
					continue;
				}

				node_t *item = NULL;
				while (!(item = (node_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(node_t))));
				item->port = (u_short)pUdpTable->table[i].dwLocalPort;
				item->address = (u_long)pUdpTable->table[i].dwLocalAddr;
				item->proto = PROTO_UDP;
				DL_APPEND(tmpList, item);

				IpAddr.S_un.S_addr = (u_long)pUdpTable->table[i].dwLocalAddr;
				strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
				//printf("\n");
				//printf("\tUDP[%d] Local Addr: %s\n", i, szLocalAddr);
				//printf("\tUDP[%d] Local Port: %d \n", i,
				//	ntohs((u_short)pUdpTable->table[i].dwLocalPort));

				//printf("\tUDP[%d] Owning PID: %d\n", i, pUdpTable->table[i].dwOwningPid);
			}
		}

		node_t *list = *pList;
		DL_CONCAT(list, tmpList);
		*pList = list;
	}
	else {
		printf("\tGetExtendedUdpTable failed with %d\n", dwRetVal);
		FREE(pUdpTable);
		return 1;
	}

	if (pUdpTable != NULL) {
		FREE(pUdpTable);
		pUdpTable = NULL;
	}

	return 0;
}

void startPortMonitor(void)
{
	int i;
	node_t *netTrashList = NULL;
	node_t *el, *el_tmp;
	struct processInfo *process;
	DWORD trashLen = 0;
	DWORD counter;

	while (TRUE)
	{
		node_t *list = NULL;
		DL_FOREACH(globalList, process)
		{
			if (process->network)
			{
				getTcpByPid(process->pidList, process->pidCount, &list);
				getUdpByPid(process->pidList, process->pidCount, &list);
			}
		}

		DL_COUNT(netGlobalList, el, counter);
		DL_CONCAT(netTrashList, netGlobalList);
		trashLen += counter;

		netGlobalList = list;
		//printf("%d\n", trashLen);
		if (trashLen > 1000) {
			i = 0;
			DL_FOREACH_SAFE(netTrashList, el, el_tmp) {
				DL_DELETE(netTrashList, el);
				free(el);
				++i;
				if (i == trashLen - 1000) {
					break;
				}
			}
			trashLen = 1000;
		}

		Sleep(10);
	}

	return;
}

void got_packet(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const struct sniff_udp *udp; /* The UDP header */
	//const char *payload; /* Packet payload */

	u_int size_ip;
	u_long ip_src, ip_dst;
	u_int size_tcp;
	u_short sport, dport;

	node_t *el;

	ethernet = (struct sniff_ethernet*)(packet);
	if (ethernet->ether_type == 0x0008) {
		// IPv4
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		ip_src = ip->ip_src.S_un.S_addr;
		ip_dst = ip->ip_dst.S_un.S_addr;
		//printf("IP: ip_src %u\n", ip_src);
		size_ip = IP_HL(ip) * 4;
		if (size_ip < 20) {
			return;
		}
		if (ip->ip_p == 6) {
			// TCP
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp) * 4;
			if (size_tcp < 20) {
				return;
			}
			sport = tcp->th_sport;
			dport = tcp->th_dport;
			//printf("TCP: sport %d\n", tcp->th_sport);
			DL_FOREACH(netGlobalList, el) {
				if (el->proto == PROTO_TCP && (el->address == ip_src && el->port == sport || el->address == ip_dst && el->port == dport)) {
					//printf("TCP: Got it\n");
					pcap_dump(dumpfile, header, packet);
					break;
				}
			}
		}
		else if (ip->ip_p == 17) {
			// UDP
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
			sport = udp->uh_sport;
			dport = udp->uh_sport;
			//printf("UDP: sport %d\n", udp->uh_sport);
			DL_FOREACH(netGlobalList, el) {
				if (el->proto == PROTO_UDP && (el->address == ip_src && el->port == sport || el->address == ip_dst && el->port == dport)) {
					//printf("UDP: Got it\n");
					pcap_dump(dumpfile, header, packet);
					break;
				}
			}
		}
		else {
			return;
		}
	}

	return;
}

void startPacketSniffer(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev = networkInterface;

	pcap_if_t *alldevs;
	pcap_if_t *d;

	/* Retrieve the device list on the local machine */

	//int iter1 = 0;

	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return ;
		//exit(1);
		//Sleep(100);
		//++iter1;
	}
	int i = 0;
	/* Print the list */
	/*
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	*/
	pcap_t * handle = pcap_open(dev, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (handle == NULL) {
		printf("Couldn't open device %s: %s\n", dev, errbuf);
		return;
		//exit(0);
	}

	char path[MAX_PATH];
	WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, outputPath, -1, path, sizeof(path), NULL, NULL);
	char dumpPath[MAX_PATH];
	WCHAR Wpath[MAX_PATH];
	WCHAR WdumpPath[MAX_PATH];
	WCHAR WolddumpPath[MAX_PATH];
	PathCombineA(dumpPath, path, "dump.pcap");

	mbstowcs(Wpath, path, MAX_PATH - 1);
	mbstowcs(WdumpPath, dumpPath, MAX_PATH - 1);

	

	if (PathFileExists(WdumpPath)) {
		PathCombineW(WolddumpPath, Wpath, TEXT("old_dump.pcap"));
		wprintf(TEXT("%s\n"), WolddumpPath);
		CopyFile(WdumpPath, WolddumpPath, FALSE);
	}

	pcap_dumper_t *dumpfile = pcap_dump_open(handle, dumpPath);

	pcap_loop(handle, -1, got_packet, (u_char *)dumpfile);

	return;
}

void StartServiceInternal() {
	//CreateProcessInternal(_T("C:\\Windows\\System32\\sc.exe"), _T("sc.exe START WindowsUpdate"));
	SC_HANDLE sc_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE service_handle = OpenService(sc_handle, TEXT("NPCAP"), SC_MANAGER_ALL_ACCESS);
	if (!service_handle) {
		printf("Failed to open service NPCAP. GLE = %d\n", GetLastError());
		fflush(stdout);
		return;
	}
	if (StartService(service_handle, 0, NULL)) {
		printf("Service NPCAP started successfully.\n");
	}
	else {
		printf("Failed to start service NPCAP. GLE = %d\n", GetLastError());
	}
}

int test_npcap() {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm *ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;


	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in test pcap_findalldevs: %s\n", errbuf);
		fflush(stderr);
		return 1;
		//exit(1);
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

	return 0;
}

int initNetwork()
{
	StartServiceInternal();
	int iter = 0;
	while (test_npcap()) {
		printf("iter %d\n", iter++);
		fflush(stdout);
		Sleep(5000);
	}

	auto *monitorWorker = new std::thread(startPortMonitor);
	auto *snifferWorket = new std::thread(startPacketSniffer);

	return 0;
}
