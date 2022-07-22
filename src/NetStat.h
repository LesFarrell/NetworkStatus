#ifndef NETSTAT_HEADER_GUARD
#define NETSTAT_HEADER_GUARD

#include "uthash.h"

// Function protypes.
int FillNetStatGrid();
void FindProcessName( DWORD processID, char *szProcessName);
int ReverseDNSLookup(char* IP, int version, int* DNSDONE);
int InitialiseWinsock();
size_t to_narrow(const wchar_t* src, char* dest, size_t dest_len);
int FilterEntryV4(PMIB_TCPTABLE2 pTcpTable2, int ientry);
int FilterEntryV6(PMIB_TCP6TABLE2 pTcpTable2, int ientry);
void loadSettings(void);
void saveSettings(void);
const char* GetPortDescription(int port);
int GetV4Connections(void);
int GetV6Connections(void);
int GetV6Connections(void);
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
    int ShowPortDescriptions;
} configuration;
configuration config;

typedef struct KeyValue
{
    int key;
    char* value;
} KeyValue;


const KeyValue PortDescriptions[] = {
    {0,""},
    {7, "(ECHO)"},
    {17, "(QOTD)"},
    {20,"(FTP)"},
    {21, "(FTP)"},
    {22, "(SSH)"},
    {23, "(TELNET)"},
    {25, "(SMTP)"},
    {42, "(WINS)"},
    {43, "(WHOIS)"},
    {53, "(DNS)"},
    {69, "(TFTP)"},
    {79, "(FINGER)"},
    {80, "(HTTP)"},
    {107, "(RTELNET)"},
    {110, "(POP3)"},
    {119, "(NNTP)"},
    {123, "(NTP)"},
    {135, "(RPC)"},
    {137, "(NETBIOS)"},
    {138, "(NETBIOS)"},
    {139, "(NETBIOS)"},
    {143, "(IMAP)"},
    {152, "(IMAP)"},
    {161, "(SNMP)"},
    {162, "(SNMP)"},
    {389, "(LDAP)"},
    {443, "(HTTPS)"},
    {444, "(SNPP)"},
    {445, "(SMB)"},
    {502, "(MODBUS)"},
    {520, "(RIP)"},
    {530, "(RPC)"},
    {531, "(IRC)"},
    {546, "(DCHP)"},
    {547, "(DCHP)"},
    {554, "(RTSP)"},
    {563, "(NNTP)"},
    {564, "(ORACLE)"},
    {587, "(SMTP)"},
    {631, "(IPP)"},
    {636, "(LDAPS)"},
    {639, "(MSDP)"},
    {647, "(DHCP)"},
    {802, "(MODBUS)"},
    {853, "(DNS/TLS)"},
    {1026, "(DCOM)"},
    {1029, "(DCOM)"},
    {1080, "(SOCKS)"},
    {1194, "(OPENVPN)"},
    {1234, "(VLC)"},
    {1883, "(MQTT)"},
    {2732, "(STEAM)"},
    {3306, "(MYSQL)"},
    {3301, "(SAP)"},
    {5000, "(UPNP)"},
    {5800, "(VNC)"},
    {5900, "(VNC)"},
    {8080, "(HTTP)"},
};

typedef struct ConnectionData{
    char Process[MAX_PATH];
    char PID[MAX_PATH];
    char LocalAddress[MAX_PATH];
    char LocalPort[MAX_PATH];
    char RemoteAddress[MAX_PATH];
    char RemotePort[MAX_PATH];
    char ReverseDNS[MAX_PATH];
    char ConnectionStatus[MAX_PATH];
    char ConnectionType[MAX_PATH];
} ConnectionData;




#endif
