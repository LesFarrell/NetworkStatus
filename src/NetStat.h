#ifndef NETSTAT_HEADER_GUARD
#define NETSTAT_HEADER_GUARD

#include "uthash.h"

// Function protypes.
int FillNetStatGrid();
void FindProcessName( DWORD processID);
int ReverseDNSLookup(char* IP);
int InitialiseWinsock();
size_t to_narrow(const wchar_t* src, char* dest, size_t dest_len);
int FilterEntry(PMIB_TCPTABLE2 pTcpTable2, int ientry);
void loadSettings(void);
void saveSettings(void);

void cb_mnuAboutBox(void);
int cb_Timer(Ihandle* ih);
void cb_mnuSettings(void);
int cb_mnuExit(void);
int cb_EnterCell(Ihandle* ih, int lin, int col);
int cb_LeaveCell(Ihandle* ih, int lin, int col);


// Hash structure for saving hostnames.
struct  hostname_struct{
    char IP[32];
    char hostname[NI_MAXHOST];
    UT_hash_handle hh;
};
struct hostname_struct *reverseDNS_Hash = NULL, *DNS_Result = NULL;
char hostname[NI_MAXHOST] = { '\0' };

typedef struct configuration
{
    int HideLocalConections;
    int DisableDNSLookup;
} configuration;
configuration config;

typedef struct KeyValue
{
    char* key;
    char* value;
} KeyValue;


const KeyValue PortDescriptions[] = {
    {"7", "ECHO"},
    {"20","FTP"},
    {"21", "FTP"},
    {"22", "SSH"},
    {"23", "TELNET"},
    {"25", "SMTP"},
    {"43", "WHOIS"},
    {"53", "DNS"},
    {"79", "FINGER"},
    {"80", "HTTP"},
    { "107", "RTELNET"},
    {"110", "POP3"},
    {"119", "NNTP"},
    {"123", "NTP"},
    {"137", "NETBIOS"},
    {"143", "IMAP"},
    {"152", "IMAP"},
    {"443", "HTTPS"},
    {"444", "SNPP"},
    {"445", "SMB"},
    {"502", "MODBUS"},
    {"530", "RPC"},
    {"554", "RTSP"},
    {"563", "NNTP"},
    {"587", "SMTP"},
    {"631", "IPP"},
    {"647", "DHCP"},
    {"802", "MODBUS"},
    {"1029", "DCOM"},
    {"1080", "SOCKS"},
    {"1194", "OPENVPN"},
    {"1234", "VLC"},
    {"1883", "MQTT"},
    {"3306", "MYSQL"},
    {"3301", "SAP"}
};
#endif