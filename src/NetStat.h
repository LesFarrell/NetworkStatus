#ifndef NETSTAT_HEADER_GUARD
#define NETSTAT_HEADER_GUARD


typedef struct  IPDetails_struct {
    char LastUpdated[512];
    char IP[32];
    char country[512];
    char city[512];
    double latitude;
    double longitude;
    char org[512];
    char isp[512];
    char domain[512];
} IPDetails_struct;
IPDetails_struct IP_Details;



// Function protypes.
int FillNetStatGrid();
void FindProcessName( DWORD processID, char *szProcessName);
int LookupIPDetails(char* IP, IPDetails_struct *IP_Details, int* DNSDONE);
int InitialiseWinsock();
size_t to_narrow(const wchar_t* src, char* dest, size_t dest_len);
void loadSettings(void);
void saveSettings(void);
const char* GetPortDescription(int port);
int SearchDatabase(char* IP, IPDetails_struct* IP_Details);
int GetV4Connections(void);
int GetV6Connections(void);
int GetV6Connections(void);
void cb_mnuAboutBox(void);
int cb_Timer(Ihandle* ih);
void cb_mnuSettings(void);
int cb_mnuExit(void);
int cb_EnterCell(Ihandle* ih, int lin, int col);
int cb_LeaveCell(Ihandle* ih, int lin, int col);
int FilterEntryV4(MIB_TCPTABLE2* pTcpTable2, int idx);
int FilterEntryV6(MIB_TCP6TABLE2* pTcpTable, int idx);
void CreateDatabase(void);
int FileExists(const char* filename);



typedef struct configuration {
    int HideLocalConections;
    int DisableDNSLookup;
    int ShowPortDescriptions;
    int ApplyPortFilter;
    char PortFilter[NI_MAXHOST];
    char WhoIs[NI_MAXHOST];
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
    {6000, "(X11)"},
    {8080, "(HTTP)"},
};

typedef struct ConnectionData{
    char Process[MAX_PATH];
    char PID[MAX_PATH];
    char LocalAddress[MAX_PATH];
    char LocalPort[MAX_PATH];
    char RemoteAddress[MAX_PATH];
    char RemotePort[MAX_PATH];
    char Country[MAX_PATH];
    char City[MAX_PATH];
    char ORG[MAX_PATH];
    char ISP[MAX_PATH];
    char DOMAIN[MAX_PATH];
    char ConnectionStatus[MAX_PATH];
    char ConnectionType[MAX_PATH];
} ConnectionData;

#endif
