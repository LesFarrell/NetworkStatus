#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <Iphlpapi.h>
#include <Tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iup.h>
#include <iupcontrols.h>
#include <iup_config.h>
#include "netstat.h"
#include "uthash.h"


// Globals.
char sStatusBarText[256];
Ihandle *iStatusbar;
Ihandle *iGrid;
Ihandle *iconfig;

/* Note: could also use malloc() and free() */
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define CALLOC(x) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))


ConnectionData *ConnectionDetails = NULL;
int NumberOfConnections = 0;


int GetV6Connections(void)
{
        // Declare and initialize variables
        PMIB_TCP6TABLE2  pTcpTable;
        DWORD dwSize = 0;
        DWORD dwRetVal = 0;
        char buffer[256] = { '\0' };
        wchar_t ipstringbuffer[46];
        int i;
        int DNSDONE = 0;

        pTcpTable = (MIB_TCP6TABLE2*)MALLOC(sizeof(MIB_TCP6TABLE2));
        if (pTcpTable == NULL) {
            printf("Error allocating memory\n");
            return 1;
        }

        dwSize = sizeof(MIB_TCP6TABLE2);
        // Make an initial call to GetTcp6Table to get the necessary size into the dwSize variable
        if ((dwRetVal = GetTcp6Table2(pTcpTable, &dwSize, TRUE)) ==
            ERROR_INSUFFICIENT_BUFFER) {
            FREE(pTcpTable);
            pTcpTable = (MIB_TCP6TABLE2*)MALLOC(dwSize);
            if (pTcpTable == NULL) {
                wprintf(L"Error allocating memory\n");
                return 1;
            }
        }
        // Make a second call to GetTcp6Table to get the actual data we require
        if ((dwRetVal = GetTcp6Table2(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {
            
            for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) 
            {
                if (FilterEntryV6(pTcpTable, i) == 0) 
                {

                    ConnectionDetails = (ConnectionData*)realloc(ConnectionDetails, ((NumberOfConnections + 1) * sizeof(ConnectionData)));
                    
                    ConnectionDetails[NumberOfConnections].Process[0] = '\0';
                    ConnectionDetails[NumberOfConnections].PID[0] = '\0';
                    ConnectionDetails[NumberOfConnections].LocalAddress[0] = '\0';
                    ConnectionDetails[NumberOfConnections].LocalPort[0] = '\0';
                    ConnectionDetails[NumberOfConnections].RemoteAddress[0] = '\0';
                    ConnectionDetails[NumberOfConnections].RemotePort[0] = '\0';
                    ConnectionDetails[NumberOfConnections].ReverseDNS[0] = '\0';
                    ConnectionDetails[NumberOfConnections].ConnectionStatus[0] = '\0';
                    ConnectionDetails[NumberOfConnections].ConnectionType[0] = '\0';
                

                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionType, sizeof(ConnectionDetails[NumberOfConnections].ConnectionType) - 1, "IPv6");

                    if (config.DisableDNSLookup == 0 && DNSDONE == 0)
                    {
                        ReverseDNSLookup(ConnectionDetails[NumberOfConnections].RemoteAddress, 1, &DNSDONE);
                        strcpy_s(ConnectionDetails[NumberOfConnections].ReverseDNS, sizeof(ConnectionDetails[NumberOfConnections].ReverseDNS) - 1, hostname);
                    }
                    else
                    {
                        strcpy_s(ConnectionDetails[NumberOfConnections].ReverseDNS, sizeof(ConnectionDetails[NumberOfConnections].ReverseDNS) - 1, ConnectionDetails[NumberOfConnections].RemoteAddress);
                        strcat_s(ConnectionDetails[NumberOfConnections].ReverseDNS, sizeof(ConnectionDetails[NumberOfConnections].ReverseDNS) - 1, "*");
                    }

                    switch (pTcpTable->table[i].State) {
                        case MIB_TCP_STATE_CLOSED:
                            sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "CLOSED");
                            break;
                        case MIB_TCP_STATE_LISTEN:
                            sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "LISTEN");
                            break;
                        case MIB_TCP_STATE_SYN_SENT:
                            sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "SYN-SENT");
                            break;
                        case MIB_TCP_STATE_SYN_RCVD:
                            sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "SYN-RECEIVED");
                            break;
                        case MIB_TCP_STATE_ESTAB:
                            sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "ESTABLISHED");
                            break;
                        case MIB_TCP_STATE_FIN_WAIT1:
                            sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "FIN-WAIT-1");
                            break;
                        case MIB_TCP_STATE_FIN_WAIT2:
                            sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "FIN-WAIT-2");
                            break;
                        case MIB_TCP_STATE_CLOSE_WAIT:
                            sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "CLOSE-WAIT");
                            break;
                        case MIB_TCP_STATE_CLOSING:
                            sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "CLOSING");
                            break;
                        case MIB_TCP_STATE_LAST_ACK:
                            sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "LAST-ACK");
                            break;
                        case MIB_TCP_STATE_TIME_WAIT:
                            sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "TIME-WAIT");
                            break;
                        case MIB_TCP_STATE_DELETE_TCB:
                            sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "DELETE-TCB");
                            break;
                        default:
                            sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "UNKNOWN");
                            break;
                    }

                    FindProcessName((DWORD)pTcpTable->table[i].dwOwningPid, ConnectionDetails[NumberOfConnections].Process);
                    sprintf_s(ConnectionDetails[NumberOfConnections].PID, sizeof(ConnectionDetails[NumberOfConnections].PID) - 1, "%d", (DWORD)pTcpTable->table[i].dwOwningPid);

                    if (InetNtop(AF_INET6, &pTcpTable->table[i].LocalAddr, ipstringbuffer, 46) == NULL) {
                        printf("  InetNtop function failed for local IPv6 address\n");
                    }
                    else
                    {
                        to_narrow(ipstringbuffer, buffer, sizeof(buffer) - 1);
                        sprintf_s(ConnectionDetails[NumberOfConnections].LocalAddress, sizeof(ConnectionDetails[NumberOfConnections].LocalAddress) - 1, "%s", buffer);
                    }                    
                    sprintf_s(ConnectionDetails[NumberOfConnections].LocalPort, sizeof(ConnectionDetails[NumberOfConnections].LocalPort) - 1,"%d", ntohs((u_short)pTcpTable->table[i].dwLocalPort));
                    
                    if (InetNtop(AF_INET6, &pTcpTable->table[i].RemoteAddr, ipstringbuffer, 46) != NULL)
                    {
                        to_narrow(ipstringbuffer, buffer,sizeof(buffer) - 1);
                        sprintf_s(ConnectionDetails[NumberOfConnections].RemoteAddress, sizeof(ConnectionDetails[NumberOfConnections].RemoteAddress) - 1, "%s", buffer);
                    }
                    //printf(L"\tTCP[%d] Remote Scope ID: %d \n", i, ntohl(pTcpTable->table[i].dwRemoteScopeId));
                    sprintf_s(ConnectionDetails[NumberOfConnections].RemotePort, sizeof(ConnectionDetails[NumberOfConnections].RemotePort) - 1, "%d", ntohs((u_short)pTcpTable->table[i].dwRemotePort));
    
                    NumberOfConnections++;
                }
            }
        }
        else {
            printf("\tGetTcp6Table failed with %d\n", dwRetVal);
            FREE(pTcpTable);
            return 1;
        }

        if (pTcpTable != NULL) {
            FREE(pTcpTable);
            pTcpTable = NULL;
        }

        return 0;
    
}

int GetV4Connections(void)
{
    // Declare and initialize variables.
    PMIB_TCPTABLE2 pTcpTable2;
    ULONG ulSize = 0;
    DWORD dwRetVal = 0;
    boolean DNS_LOOKUP = FALSE;
    char szLocalAddr[128] = { '\0' };
    char szRemoteAddr[128] = { '\0' };
    struct in_addr IpAddr;
    char buffer[256] = { '\0' };
    int i = 0;
    int DNSDONE = 0;
   
    pTcpTable2 = (MIB_TCPTABLE2*)MALLOC(sizeof(MIB_TCPTABLE2));
    if (pTcpTable2 == NULL) {
        printf("Error allocating memory\n");
        return 1;
    }

    ulSize = sizeof(MIB_TCPTABLE2);

    // Make an initial call to GetTcpTable to get the necessary size into the ulSize variable.
    if ((dwRetVal = GetTcpTable2(pTcpTable2, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
        FREE(pTcpTable2);
        pTcpTable2 = (MIB_TCPTABLE2*)MALLOC(ulSize);
        if (pTcpTable2 == NULL) {
            printf("Error allocating memory\n");
            return 1;
        }
    }

    // Make a second call to GetTcpTable to get the actual data we require.
    if ((dwRetVal = GetTcpTable2(pTcpTable2, &ulSize, TRUE)) == NO_ERROR) {        
        
        for (i = 0; i < (int)pTcpTable2->dwNumEntries; i++) {

            if (FilterEntryV4(pTcpTable2, i) == 0) {
                ConnectionDetails = (ConnectionData *) realloc (ConnectionDetails, ((NumberOfConnections + 1) * sizeof(ConnectionData)));


                ConnectionDetails[NumberOfConnections].Process[0] = '\0';
                ConnectionDetails[NumberOfConnections].PID[0] = '\0';
                ConnectionDetails[NumberOfConnections].LocalAddress[0] = '\0';
                ConnectionDetails[NumberOfConnections].LocalPort[0] = '\0';
                ConnectionDetails[NumberOfConnections].RemoteAddress[0] = '\0';
                ConnectionDetails[NumberOfConnections].RemotePort[0] = '\0';
                ConnectionDetails[NumberOfConnections].ReverseDNS[0] = '\0';
                ConnectionDetails[NumberOfConnections].ConnectionStatus[0] = '\0';
                ConnectionDetails[NumberOfConnections].ConnectionType[0] = '\0';


                // Process Name.
                FindProcessName((DWORD)pTcpTable2->table[i].dwOwningPid, ConnectionDetails[NumberOfConnections].Process);

                // Display the Process PID.
                sprintf_s(ConnectionDetails[NumberOfConnections].PID, sizeof(ConnectionDetails[NumberOfConnections].PID) - 1, "%d", (DWORD)pTcpTable2->table[i].dwOwningPid);
                
                // Local address.
                IpAddr.S_un.S_addr = (u_long)pTcpTable2->table[i].dwLocalAddr;
                strcpy_s(ConnectionDetails[NumberOfConnections].LocalAddress, sizeof(ConnectionDetails[NumberOfConnections].LocalAddress) - 1, inet_ntoa(IpAddr));
                
                // Local port.
                sprintf_s(ConnectionDetails[NumberOfConnections].LocalPort, sizeof(ConnectionDetails[NumberOfConnections].LocalPort) - 1, "%d", ntohs((u_short)pTcpTable2->table[i].dwLocalPort));
                
                // Remote address.
                IpAddr.S_un.S_addr = (u_long)pTcpTable2->table[i].dwRemoteAddr;
                strcpy_s(ConnectionDetails[NumberOfConnections].RemoteAddress, sizeof(ConnectionDetails[NumberOfConnections].RemoteAddress) - 1, inet_ntoa(IpAddr));
                
                // Remote port.
                sprintf_s(ConnectionDetails[NumberOfConnections].RemotePort, sizeof(ConnectionDetails[NumberOfConnections].RemotePort) - 1,"%d ", ntohs((u_short)pTcpTable2->table[i].dwRemotePort));
                if (config.ShowPortDescriptions == 1)
                {
                    strcat_s(ConnectionDetails[NumberOfConnections].RemotePort, sizeof(ConnectionDetails[NumberOfConnections].RemotePort) - 1, GetPortDescription(atoi(ConnectionDetails[NumberOfConnections].RemotePort)));
                }
                

                // Only do the Reverse DNS if it's turned on and even then just do one lookup per call to this function, as it's a slow process.
                if (config.DisableDNSLookup == 0 && DNSDONE == 0)
                {
                    ReverseDNSLookup(ConnectionDetails[NumberOfConnections].RemoteAddress,0, &DNSDONE);
                    strcpy_s(ConnectionDetails[NumberOfConnections].ReverseDNS, sizeof(ConnectionDetails[NumberOfConnections].ReverseDNS) - 1, hostname);                                            
                }
                else
                {
                    strcpy_s(ConnectionDetails[NumberOfConnections].ReverseDNS, sizeof(ConnectionDetails[NumberOfConnections].ReverseDNS) - 1, ConnectionDetails[NumberOfConnections].RemoteAddress);
                    strcat_s(ConnectionDetails[NumberOfConnections].ReverseDNS, sizeof(ConnectionDetails[NumberOfConnections].ReverseDNS) - 1, "*");
                }

                // Display Socket states.
                switch (pTcpTable2->table[i].dwState) {
                case MIB_TCP_STATE_CLOSED:
                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "CLOSED");
                    break;
                case MIB_TCP_STATE_LISTEN:
                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "LISTEN");
                    break;
                case MIB_TCP_STATE_SYN_SENT:
                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "SYN-SENT");
                    break;
                case MIB_TCP_STATE_SYN_RCVD:
                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "SYN-RECIVED");
                    break;
                case MIB_TCP_STATE_ESTAB:
                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "ESTABLISHED");
                    break;
                case MIB_TCP_STATE_FIN_WAIT1:
                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "FIN-WAIT1");
                    break;
                case MIB_TCP_STATE_FIN_WAIT2:
                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "FIN-WAIT2");
                    break;
                case MIB_TCP_STATE_CLOSE_WAIT:
                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "CLOSE-WAIT");
                    break;
                case MIB_TCP_STATE_CLOSING:
                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "CLOSING");
                    break;
                case MIB_TCP_STATE_LAST_ACK:
                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "LAST-ACK");
                    break;
                case MIB_TCP_STATE_TIME_WAIT:
                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "TIME-WAIT");
                    break;
                case MIB_TCP_STATE_DELETE_TCB:
                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "DELETE-TCB");
                    break;
                default:
                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionStatus, sizeof(ConnectionDetails[NumberOfConnections].ConnectionStatus) - 1, "%s", "UNKNOWN");
                    break;
                }                
                
                // Connection type IPv4 or ipv6
                sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionType, sizeof(ConnectionDetails[NumberOfConnections].ConnectionType) - 1, "IPv4");
                NumberOfConnections++;
            }
        }
    }
    else {
        printf("\tGetTcpTable failed with %d\n", dwRetVal);
        FREE(pTcpTable2);
        return 1;
    }

    if (pTcpTable2 != NULL) {
        FREE(pTcpTable2);
        pTcpTable2 = NULL;
    }

    return 0;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

const char* GetPortDescription(int port) {    
    int Start = 0;
    int MID = 0;
    int low = 0;
    int high = 35 - 1;
    int median = 0;    

    // Do a Binary search on the port description array.
    do
    {
        median = (low + high) / 2;
        if (port < PortDescriptions[median].key) 
        {
            high = median - 1;
        }
        else
        {
            low = median + 1;
        }
    } while ((port != PortDescriptions[median].key) && low <= high);

    if (port ==  PortDescriptions[median].key) {
        return PortDescriptions[median].value;
    }
    else {
        return PortDescriptions[0].value;
    }
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

int cb_EnterCell(Ihandle* ih, int lin, int col) {
    IupSetAttributeId2(ih, "MARK", lin, 0, "1");
    return IUP_DEFAULT;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

int cb_LeaveCell(Ihandle* ih, int lin, int col) {
    IupSetAttributeId2(ih, "MARK", lin, 0, "0");
    return IUP_DEFAULT;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/*
 * Function: mnuaboutbox_cb
 * Show the applications about box.
 *
 * Parameters:
 * void.
 *
 * Returns:
 * void.
 */
void cb_mnuAboutBox(void) {
    char buffer[2048];
    strcpy_s(buffer,sizeof(buffer) -1, "Network Status by Les Farrell");
    strcat_s(buffer, sizeof(buffer) - 1, "\n\nIUP GUI Toolkit: ");
    strcat_s(buffer, sizeof(buffer) - 1, IupGetGlobal("VERSION"));
    strcat_s(buffer, sizeof(buffer) - 1, "\n\nCopyright 2022 Les Farrell");
    strcat_s(buffer, sizeof(buffer) - 1, "\nLast compiled at ");
    strcat_s(buffer, sizeof(buffer) - 1, __TIME__);
    strcat_s(buffer, sizeof(buffer) - 1, " on ");
    strcat_s(buffer, sizeof(buffer) - 1, __DATE__);
    IupMessage("About", buffer);
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

int cb_Timer(Ihandle *ih) {
  FillNetStatGrid();
  return IUP_DEFAULT;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

int cb_mnuExit(void) {
  return IUP_CLOSE;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/*
 * Function: mnuSettings_cb
 * Show the settings dialog and apply the settings
 *
 * Parameters:
 * None.
 *
 * Returns:
 * void.
 */
void cb_mnuSettings(void) {
    int result;

    loadSettings();

    // Build up the dialog and show it.
    result = IupGetParam("Settings", NULL, 0,
        "Hide connections to 127.0.0.0 / 0.0.0.0 : %b\n"
        "Disable Reverse DNS Lookup : %b\n"
        "Show Port Descriptions : %b\n"
        , &config.HideLocalConections, &config.DisableDNSLookup, &config.ShowPortDescriptions);
    if (result == 1) {
        saveSettings();
    }

    return;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

void loadSettings(void) {
    // Read the current settings.
    config.HideLocalConections = IupConfigGetVariableIntDef(iconfig, "NetStat", "HideLocal", 1);
    config.DisableDNSLookup = IupConfigGetVariableIntDef(iconfig, "NetStat", "DisableDNS", 0);
    config.ShowPortDescriptions = IupConfigGetVariableIntDef(iconfig, "NetStat", "ShowPortDescriptions", 1);
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

void saveSettings(void) {
    // Save the updated settings.
    IupConfigSetVariableInt(iconfig, "NetStat", "HideLocal", config.HideLocalConections);
    IupConfigSetVariableInt(iconfig, "NetStat", "DisableDNS", config.DisableDNSLookup);
    IupConfigSetVariableInt(iconfig, "NetStat", "ShowPortDescriptions", config.ShowPortDescriptions);
    IupConfigSave(iconfig);
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/*
 * Function: to_narrow
 * Converts a wide character array to a char array for use in C strings
 *
 * Parameters:
 * src  - Pointer to source wchar string
 * dest - Pointer to destination char string
 * dest_len - Size of the destination string array.
 *
 * Returns:
 * Number of chars extracted from the wide char string.
 */
size_t to_narrow(const wchar_t* src, char* dest, size_t dest_len) {
    size_t i = 0;
    wchar_t code;

    while (src[i] != '\0' && i < (dest_len - 1)) {
        code = src[i];
        if (code < 128)
            dest[i] = (char) code;
        else {
            dest[i] = '?';
            // lead surrogate, skip the next code unit, which is the trail
            if (code >= 0xD800 && code <= 0xD8FF) {                
                i++;
            }
        }
        i++;
    }
    dest[i] = '\0';
    return i - 1;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/*
 * Function: FindProcessName
 * Finds the name of an executable given it's process ID
 *
 * Parameters:
 * processID - PID of the process we are looking for.
 *
 * Returns:
 * void
 */
void FindProcessName( DWORD processID, char* szProcessName) {
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
    
	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0);
	if( hProcessSnap == INVALID_HANDLE_VALUE ) {
		return;
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof( PROCESSENTRY32 );

	// Retrieve information about the first process, and exit if unsuccessful.
	if(!Process32First( hProcessSnap, &pe32)) {
        // Must clean up the snapshot handle.
        CloseHandle( hProcessSnap );    
		return;
	}

    // Search for the requested process ID.
    while(processID != pe32.th32ProcessID) {
        Process32Next(hProcessSnap, &pe32);
	} 
    
    // Have we found a match?
    if (processID == pe32.th32ProcessID) {
        to_narrow(pe32.szExeFile, szProcessName, MAX_PATH);
    }
    else {
        strcpy_s(szProcessName, sizeof(szProcessName) - 1, "<Unknown>");
    }

    // Must clean up the snapshot handle.
	CloseHandle( hProcessSnap );
	return;	
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/*
 * Function: FillNetStatGrid
 * Fills a list with the connection details
 *
 * Parameters:
 * None
 *
 * Returns:
 * Status code
 */
int FillNetStatGrid() {
    NumberOfConnections = 0;

    // GetV4Connections();
    GetV6Connections();


    // Set the number of visible lines in the grid
    IupSetInt(iGrid, "NUMLIN", NumberOfConnections);

    // Loop and display each connection
    for (int row = 0; row <= NumberOfConnections; row++)
    {
        IupSetAttributeId2(iGrid, "", row + 1, 1, ConnectionDetails[row].Process);          // Process Name.
        IupSetAttributeId2(iGrid, "", row + 1, 2, ConnectionDetails[row].PID);              // Display the Process PID.        
        IupSetAttributeId2(iGrid, "", row + 1, 3, ConnectionDetails[row].LocalAddress);     // Local address.      
        IupSetAttributeId2(iGrid, "", row + 1, 4, ConnectionDetails[row].LocalPort);        // Local port.
        IupSetAttributeId2(iGrid, "", row + 1, 5, ConnectionDetails[row].RemoteAddress);    // Remote address.
        IupSetAttributeId2(iGrid, "", row + 1, 6, ConnectionDetails[row].RemotePort);       // Remote port.              
        IupSetAttributeId2(iGrid, "", row + 1, 7, ConnectionDetails[row].ReverseDNS);       // Reverse DNS.        
        IupSetAttributeId2(iGrid, "", row + 1, 8, ConnectionDetails[row].ConnectionStatus); // Connection Status.
        IupSetAttributeId2(iGrid, "", row + 1, 9, ConnectionDetails[row].ConnectionType);   // Connection Type.        
    }
    // Force a grid redraw.
    IupSetAttribute(iGrid, "REDRAW", "ALL");


    sprintf_s(sStatusBarText, sizeof(sStatusBarText) - 1, "Number of Entries : %d", NumberOfConnections);
    if (config.DisableDNSLookup == 1) strcat_s(sStatusBarText, sizeof(sStatusBarText) - 1, " (* Reverse DNS Disabled)");
    IupSetAttribute(iStatusbar, "TITLE", sStatusBarText);

    return 0;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/*
 * Function: ReverseDNSLookup
 * Tries to do a reverse lookup on the passed IP address.
 *
 * Parameters:
 * IP - String containing the remote IP address.
 *
 * Returns:
 * Status code
 */
int ReverseDNSLookup(char* IP, int version, int *DNSDONE) {
    DWORD dwRetval;
    struct sockaddr_in saGNI;
    struct sockaddr_in6 saGNI6;
    char servInfo[NI_MAXSERV];
    u_short port = 27015;
    

    HASH_FIND_STR(reverseDNS_Hash, IP, DNS_Result);
    
    if (!DNS_Result) {
        *DNSDONE = 1;

        
        

        // Call getnameinfo.

        //IPv4
        if (version == 0)
        {
            // Set up sockaddr_in structure which is passed to the getnameinfo function.
            saGNI.sin_family = AF_INET;
            saGNI.sin_addr.s_addr = inet_addr(IP);
            saGNI.sin_port = htons(port);
            dwRetval = getnameinfo((struct sockaddr*)&saGNI, sizeof(struct sockaddr), hostname, NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);
        }
        else
        {
            
            //IPv6

            // Set up sockaddr_in structure which is passed to the getnameinfo function.
            
            saGNI6.sin6_family = AF_INET;
            //FIXME
            memcpy(saGNI6.sin6_addr.s6_addr, (char*) IP, sizeof( IP));            
            //saGNI6.sin6_addr = inet_addr(IP);
            saGNI6.sin6_port = htons(port);
            dwRetval = getnameinfo((struct sockaddr*)&saGNI6, sizeof(struct sockaddr), hostname, NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);
            //strcpy_s(hostname, sizeof(hostname) - 1, "");
        }
        if (dwRetval != 0) {
            printf("getnameinfo failed with error # %ld\n", WSAGetLastError());
            return 255;
        }
        else {
            // Store the result in the hash table.
            DNS_Result = (struct hostname_struct *) malloc(sizeof * DNS_Result);
            strcpy_s(DNS_Result->IP, sizeof(DNS_Result->IP) - 1, IP);
            strcpy_s(DNS_Result->hostname,sizeof(DNS_Result->hostname) - 1, hostname);
            HASH_ADD_STR(reverseDNS_Hash, IP, DNS_Result);
            strcpy_s(hostname, sizeof(hostname) - 1, DNS_Result->hostname);
        }
        return 1;
    }
    *DNSDONE = 0;
    strcpy_s(hostname, sizeof(hostname) - 1, DNS_Result->hostname);
    return 0;    
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/*
 * Function: Initialise Winsock
 * Initialise then Winsock library.
 *
 * Parameters:
 * Nothing
 *
 * Returns:
 * Status Code
 */
int InitialiseWinsock() {
    WSADATA wsaData = { 0 };
    int iResult = 0;

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }
    return 0;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/*
 * Function: FilterEntry
 * Checks to see if we should show the passed entry in the grid or not
 *
 * Parameters:
 * PMIB_TCPTABLE2  - Array of the TCP/IP results.
 * ientry - The entry in the array to check.
 *
 * Returns:
 * 1 = Don't show the entry, 0 = Okay to show.
 */
int FilterEntryV4(PMIB_TCPTABLE2 pTcpTable2, int ientry)
{
    struct in_addr IpAddr;    
    char szLocalAddr[128] = { '\0' };
    char szRemoteAddr[128] = { '\0' };

    if (config.HideLocalConections == 1)
    {
        // Filter Local Addresses.
        IpAddr.S_un.S_addr = (u_long)pTcpTable2->table[ientry].dwLocalAddr;
        strcpy_s(szLocalAddr, sizeof(szLocalAddr) - 1, inet_ntoa(IpAddr));     
        if (strstr(szLocalAddr,"0.0.0.0") != NULL || strstr(szLocalAddr,"127.0.0.1") != NULL) {
            return 1;
        }

        // Filter Remote Addresses.
        IpAddr.S_un.S_addr = (u_long)pTcpTable2->table[ientry].dwRemoteAddr;
        strcpy_s(szRemoteAddr, sizeof(szRemoteAddr) - 1, inet_ntoa(IpAddr));
        if (strstr(szRemoteAddr, "0.0.0.0") != NULL || strstr(szRemoteAddr, "127.0.0.1") != NULL) {
            return 1;
        }
    }
    return 0;
}


int FilterEntryV6(PMIB_TCP6TABLE2 pTcp6Table2, int ientry)
{
    struct in_addr IpAddr;
    char szLocalAddr[128] = { '\0' };
    char szRemoteAddr[128] = { '\0' };

    // FIXME
    if (config.HideLocalConections == 1)
    {     
        // Filter Local Addresses.
        // InetNtop(AF_INET6, pTcp6Table2.table[ientry].LocalAddr, szLocalAddr, 46);
        if (strstr(szLocalAddr, "0.0.0.0") != NULL || strstr(szLocalAddr, "127.0.0.1") != NULL) {
            return 1;
        }

        // Filter Remote Addresses.
        // InetNtop(AF_INET6, pTcp6Table2->table[ientry].RemoteAddr, szRemoteAddr, 46);
        if (strstr(szRemoteAddr, "0.0.0.0") != NULL || strstr(szRemoteAddr, "127.0.0.1") != NULL) {
            return 1;
        }
    }
    return 0;
}




//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/*
 * Function: main
 * The programs main entry point.
 *
 * Parameters:
 * argc - Number of command line arguments.
 * argv - Array of command line strings.
 *
 * Returns:
 * Status Code
 */
int main(int argc, char* argv[]) {
    Ihandle *iDialog;
    Ihandle *iVbox;
    Ihandle *iTimer;
    Ihandle *file_menu, *item_exit;
    Ihandle *filesub_menu, *menu;
    Ihandle *options_menu, *item_settings;
    Ihandle *optionsub_menu;
    Ihandle *item_about;
    Ihandle *help_menu, *helpsub_menu;
    Ihandle *item_quickFilter, *item_quickFilterPortHTTP, *item_quickFilterPortHTTPS;
    
    struct hostname_struct* tmpDNS = NULL;

    // Initialise IUP.
    if (IupOpen(&argc, &argv) == IUP_ERROR) return 0;

    IupSetGlobal("PROCESSWINDOWSGHOSTING", "NO");

    // Initialise IUP Controls.
    IupControlsOpen();

    // Initialise Winsock.
    InitialiseWinsock();

    // Setup the file menu.
    item_exit = IupItem("Exit", NULL);
    IupSetCallback(item_exit, "ACTION", (Icallback)cb_mnuExit);
    file_menu = IupMenu(item_exit, NULL);
    filesub_menu = IupSubmenu("File", file_menu);

    // Setup the options menu.
    item_settings = IupItem("Settings", NULL);
    item_quickFilter = IupItem("Quick Filter", NULL);
    item_quickFilterPortHTTP = IupItem("HTTP (80)", NULL);
    item_quickFilterPortHTTPS = IupItem("HTTPS (443)", NULL);    


    IupSetCallback(item_settings, "ACTION", (Icallback)cb_mnuSettings);
    options_menu = IupMenu(item_settings, item_quickFilter , NULL);
    optionsub_menu = IupSubmenu("Options", options_menu);

    // Setup the help menu.
    item_about = IupItem("About", NULL);
    help_menu = IupMenu(item_about, NULL);
    helpsub_menu = IupSubmenu("Help", help_menu);
    IupSetCallback(item_about, "ACTION", (Icallback)cb_mnuAboutBox);

    // Define the programs main menu.
    menu = IupMenu(filesub_menu, optionsub_menu, helpsub_menu, NULL);

    // Define the Controls.
    
    // Define the status bar.
    iStatusbar = IupLabel("");
    IupSetAttribute(iStatusbar, "PADDING", "10x5");

    // Define the matrix.
    iGrid = IupMatrixEx();

    // Grid attributes.
    IupSetAttribute(iGrid, "FLAT", "YES");
    IupSetAttribute(iGrid, "NUMCOL", "9");    
    IupSetAttribute(iGrid, "EXPAND", "YES");
    IupSetAttribute(iGrid, "RESIZEMATRIX", "YES");
    IupSetAttribute(iGrid, "MARKMODE", "LIN");
    IupSetAttribute(iGrid, "READONLY", "YES");
    IupSetAttribute(iGrid, "MENUCONTEXT", "NO");

    // Grid column titles.
    IupSetAttributeId2(iGrid, "", 0, 1, "Process");
    IupSetAttributeId2(iGrid, "", 0, 2, "PID");
    IupSetAttributeId2(iGrid, "", 0, 3, "Local Address");
    IupSetAttributeId2(iGrid, "", 0, 4, "Local Port");
    IupSetAttributeId2(iGrid, "", 0, 5, "Remote Address");
    IupSetAttributeId2(iGrid, "", 0, 6, "Remote Port");
    IupSetAttributeId2(iGrid, "", 0, 7, "Reverse DNS");
    IupSetAttributeId2(iGrid, "", 0, 8, "Connection Status");
    IupSetAttributeId2(iGrid, "", 0, 9, "Type");

    // Grid column widths.
    IupSetAttribute(iGrid, "WIDTH1", "110");
    IupSetAttribute(iGrid, "WIDTH2", "30");
    IupSetAttribute(iGrid, "WIDTH3", "55");
    IupSetAttribute(iGrid, "WIDTH4", "55");
    IupSetAttribute(iGrid, "WIDTH5", "60");
    IupSetAttribute(iGrid, "WIDTH6", "55");
    IupSetAttribute(iGrid, "WIDTH7", "175");
    IupSetAttribute(iGrid, "WIDTH8", "80");
    IupSetAttribute(iGrid, "WIDTH9", "50");

    // Grid column alignments.    
    IupSetAttribute(iGrid, "ALIGNMENT1", "ALEFT");
    IupSetAttribute(iGrid, "ALIGNMENT2", "ALEFT");        
    IupSetAttribute(iGrid, "ALIGNMENT3", "ALEFT");
    IupSetAttribute(iGrid, "ALIGNMENT4", "ALEFT");
    IupSetAttribute(iGrid, "ALIGNMENT5", "ALEFT");
    IupSetAttribute(iGrid, "ALIGNMENT6", "ALEFT");
    IupSetAttribute(iGrid, "ALIGNMENT7", "ALEFT");
    IupSetAttribute(iGrid, "ALIGNMENT8", "ALEFT");
    IupSetAttribute(iGrid, "ALIGNMENT9", "ALEFT");
    
    // Grid callbacks.
    IupSetCallback(iGrid, "ENTERITEM_CB", (Icallback)cb_EnterCell);
    IupSetCallback(iGrid, "LEAVEITEM_CB", (Icallback)cb_LeaveCell);

    // Initialise dialog control layout.
    iVbox = IupVbox(
        iGrid,
        iStatusbar,
        NULL);
    IupSetAttribute(iVbox, "EXPAND", "YES");
    
    // Dialog attributes.
    iDialog = IupDialog(iVbox);
    IupSetAttributeHandle(iDialog, "MENU", menu);
    IupSetAttribute(iDialog, "SIZE", "745xHALF");
    IupSetAttribute(iDialog, "TITLE", "Network Status by Les Farrell");
    IupSetAttribute(iDialog, "SHRINK", "YES");
    IupSetAttribute(iDialog, "ICON", "network.ico");
    IupSetAttribute(iDialog, "BACKGROUND", "255,128,255");

    // Timer attributes.
    iTimer = IupTimer();
    IupSetAttribute(iTimer, "TIME", "4000");
    IupSetAttribute(iTimer, "RUN", "YES");
    IupSetCallback(iTimer, "ACTION_CB", (Icallback)cb_Timer);

    // Status bar attributes.
    IupSetAttribute(iStatusbar, "NAME", "STATUSBAR");
    IupSetAttribute(iStatusbar, "EXPAND", "HORIZONTAL");
    IupSetAttribute(iStatusbar, "PADDING", "10x5");

    // Initialise Configuration system.
    iconfig = IupConfig();
    IupSetAttribute(iconfig, "APP_NAME", "NetStat");

    // Load the configuration settings.
    IupConfigLoad(iconfig);
    loadSettings();

    // Show the main dialog.
    IupShow(iDialog);
        
    // Fill the tcp details.
    FillNetStatGrid();

    // IUP main loop.
    IupMainLoop();

    // Detroy the IUP controls.
    IupDestroy(iGrid);
    IupDestroy(iVbox);
    IupDestroy(iTimer);
    IupDestroy(iStatusbar);
    IupDestroy(iDialog);

    // Save the current configuration.
    IupConfigSave(iconfig);

    if (ConnectionDetails != NULL) free(ConnectionDetails);

    // Free the DNS hash table contents.
    HASH_ITER(hh, reverseDNS_Hash, DNS_Result, tmpDNS) {
        HASH_DEL(reverseDNS_Hash, DNS_Result);
        free(DNS_Result);
    }

    // Close down IUP
    IupClose();

    return 0;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
