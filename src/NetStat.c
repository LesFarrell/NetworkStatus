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
#include <sqlite3.h>
#include <shlobj.h>
#include <cjson.h>
#include "httprequest.h"


// Global Variables
Ihandle *iStatusbar;                        // StatusBar handle.
Ihandle *iGrid;                             // Matrix handle.
Ihandle *iconfig;                           // Applications configuration handle.
Ihandle* iTimer;
char sStatusBarText[256];                   // Holds the contents of the statusbar text.
ConnectionData* ConnectionDetails = NULL;   // Array of filtered connection details.
int NumberOfConnections = 0;                // Number of entries in connection details array.
int SortColumn = 0;
int SortDirection = 0;
char CurrentIP[32] = { "0.0.0.0" };
int CurrentLine = 0;

WSADATA wsaData = { 0 };


// Note: could also use malloc() and free()
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define CALLOC(x) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (x))
#define FREE(x)   HeapFree(GetProcessHeap(), 0, (x))



/*---------------------------------------------------------------------------------------
 * Function: strsplit
 * Based on a Nice function found on stackoverflow which splits a string into an array .
 *
 * Parameters:
 *          str - Pointer to the string to split *
 *          c   - The delimiter character
 *          arr - Pointer to the array to create. (defined a char **array)
 *
 * Returns:
 *          int - The number of items in the created array
 *
 * Notes:
 *          Remember to free the created array once done.
 *
 ---------------------------------------------------------------------------------------*/
int strsplit(char* str, char c, char*** arr)
{
    int count = 1;
    int token_len = 1;
    int i = 0;
    char* p;
    char* t;

    p = str;
    while (*p != '\0') {
        if (*p == c) count++;
        p++;
    }

    *arr = (char**)malloc(sizeof(char*) * count);
    if (*arr == NULL) exit(1);

    p = str;
    while (*p != '\0')
    {
        if (*p == c)
        {
            (*arr)[i] = (char*) malloc(sizeof(char) * token_len);
            if ((*arr)[i] == NULL) exit(1);
            token_len = 0;
            i++;
        }
        p++;
        token_len++;
    }
    (*arr)[i] = (char*) malloc(sizeof(char) * token_len);
    if ((*arr)[i] == NULL) exit(1);

    i = 0;
    p = str;
    t = ((*arr)[i]);
    while (*p != '\0')
    {
        if (*p != c && *p != '\0')
        {
            *t = *p;
            t++;
        }
        else
        {
            *t = '\0';
            i++;
            t = (char*) ((*arr)[i]);
        }
        p++;
    }

    return count;
}



/*---------------------------------------------------------------------------------------
 * Function: FilterIPv4Entries
 * Tests to see if the entry should be filtered.
 *
 * Parameters:
 * MIB_TCPTABLE2 *pTcpTable2 - Table containing the connection details.
 * int idx  - Entry in the table we are testing.
 *
 * Returns:
 * 1 = Don't show the entry as it's been filtered. 0 = Show the entry as normal.
 *
 *---------------------------------------------------------------------------------------*/
int FilterIPv4Entries(MIB_TCPTABLE2 *pTcpTable2, int idx)
{    
    char RemoteAddress[256] = { '\0' };
    char LocalAddress[256] = { '\0' };
    char LocalPort[256] = { '\0' };
    char RemotePort[256] = { '\0' };
    struct in_addr IpAddr;
    int numtokens = 0;
    char **arr = NULL;
    int retvalue = 0;
    int i = 0;

    if (config.HideLocalConections == 1) {

        IpAddr.S_un.S_addr = (u_long) pTcpTable2->table[idx].dwLocalAddr;
        strcpy_s(LocalAddress, sizeof(LocalAddress) - 1, inet_ntoa(IpAddr));

        IpAddr.S_un.S_addr = (u_long) pTcpTable2->table[idx].dwRemoteAddr;
        strcpy_s(RemoteAddress, sizeof(RemoteAddress) - 1, inet_ntoa(IpAddr));        

        if (strstr(LocalAddress, "0.0.0.0") != NULL || strstr(LocalAddress, "127.0.0.1") != NULL) {
            return 1;
        }

        if (strstr(RemoteAddress, "0.0.0.0") !=NULL || strstr(RemoteAddress, "127.0.0.1") != NULL) {
            return 1;
        }        
    }

    // Split the string and find the num of tokens.
    if (config.ApplyPortFilter == 1 && strlen(config.PortFilter) > 0) {
        numtokens = strsplit(config.PortFilter, ',', &arr);

        // Check the local ports
        retvalue = 1;

        for (i = 0; i < numtokens; i++) {            
            if (atoi(arr[i]) == ntohs((u_short)pTcpTable2->table[idx].dwLocalPort)) {
                retvalue = 0;
            }
        }

        // Check the remote ports
        for (i = 0; i < numtokens; i++) {            
            if (atoi(arr[i]) == ntohs((u_short)pTcpTable2->table[idx].dwRemotePort)) {
                retvalue = 0;
            }
        }

        // Free up the memory allocated for each element
        for (i = numtokens - 1; i >= 0; i--) free(arr[i]);

        // Free the array pointer itself.
        free(arr);
    }

    return retvalue;

}



/*---------------------------------------------------------------------------------------
 * Function: FilterIPv6Entries
 * Tests to see if the entry should be filtered.
 *
 * Parameters:
 * MIB_TCP6TABLE2 *pTcpTable - Table containing the connection details.
 * int idx  - Entry in the table we are testings.
 *
 * Returns:
 * 1 = Don't show the entry as it's been filtered. 0 = Show the entry as normal.
 *
 ---------------------------------------------------------------------------------------*/
int FilterIPv6Entries(MIB_TCP6TABLE2 *pTcpTable, int idx)
{
    wchar_t ipstringbuffer[46];
    char RemoteAddress[256] = { '\0' };
    char LocalAddress[256] = { '\0' };
    int numtokens = 0;
    char** arr = NULL;
    int retvalue = 0;
    int i = 0;

    if (config.HideLocalConections == 1) {

        if (InetNtop(AF_INET6, &pTcpTable->table[idx].LocalAddr, ipstringbuffer, 46) != NULL) {
            to_narrow(ipstringbuffer, LocalAddress, sizeof(LocalAddress) - 1);
        }

        if (InetNtop(AF_INET6, &pTcpTable->table[idx].RemoteAddr, ipstringbuffer, 46) != NULL) {
            to_narrow(ipstringbuffer, RemoteAddress, sizeof(RemoteAddress) - 1);
        }

        if (strstr(LocalAddress, "::") != NULL || strstr(LocalAddress, "::1") != NULL) {
            return 1;
        }

        if (strstr(RemoteAddress, "::") != NULL || strstr(RemoteAddress, "::1") != NULL) {
            return 1;
        }
    }

    // Split the string and find the num of tokens.
    if (config.ApplyPortFilter == 1 && strlen(config.PortFilter) > 0) {
        numtokens = strsplit(config.PortFilter, ',', &arr);

        // Check the local ports
        retvalue = 1;

        for (i = 0; i < numtokens; i++) {            
            if (atoi(arr[i]) == ntohs((u_short)pTcpTable->table[idx].dwLocalPort)) {
                retvalue = 0;
            }
        }

        // Check the remote ports
        for (i = 0; i < numtokens; i++) {
            if (atoi(arr[i]) == ntohs((u_short)pTcpTable->table[idx].dwRemotePort)) {
                retvalue = 0;
            }
        }

        // Free up the memory allocated for each element
        for (i = numtokens - 1; i >= 0; i--) free(arr[i]);

        // Free the array pointer itself.
        free(arr);
    }

    return retvalue;
}



/*---------------------------------------------------------------------------------------
 * Function: GetIPv6Connections
 * Get and fill the connection details with IPv6 details.
 *
 * Parameters:
 * void.
 *
 * Returns:
 * 0 = Function successful. 1 = Error Occurred.
 *
 * Notes:
 * Fills ConnectionDetails will the details on the IPv4 connections.
 * 
 ---------------------------------------------------------------------------------------*/
int GetIPv6Connections(void)
{
        // Declare and initialize variables
        PMIB_TCP6TABLE2  pTcpTable;
        DWORD dwSize = 0;
        DWORD dwRetVal = 0;
        char buffer[256] = { '\0' };
        wchar_t ipstringbuffer[46];
        int i;
        int COUNTRY_LOOKUP_DONE = 0;

        if (config.HideIPv6 == 1) return 0;

        pTcpTable = (MIB_TCP6TABLE2*)MALLOC(sizeof(MIB_TCP6TABLE2));
        if (pTcpTable == NULL) {
            fprintf(stderr,"Error allocating memory\n");
            return 1;
        }


        // Make an initial call to GetTcp6Table to get the necessary size into the dwSize variable
        dwSize = sizeof(MIB_TCP6TABLE2);
        if ((dwRetVal = GetTcp6Table2(pTcpTable, &dwSize, TRUE)) ==
            ERROR_INSUFFICIENT_BUFFER) {
            FREE(pTcpTable);
            pTcpTable = (MIB_TCP6TABLE2*)MALLOC(dwSize);
            if (pTcpTable == NULL) {
                fprintf(stderr,"Error allocating memory\n");
                return 1;
            }
        }

        // Make a second call to GetTcp6Table to get the actual data we require
        if ((dwRetVal = GetTcp6Table2(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {
            for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
                if (FilterIPv6Entries(pTcpTable, i) == 0) 
                {                   
                    ConnectionDetails = (ConnectionData*) realloc(ConnectionDetails, ((NumberOfConnections + 1) * sizeof(ConnectionData)));                    
                    if (ConnectionDetails == NULL) break;
                    memset(&ConnectionDetails[NumberOfConnections], 0, sizeof(ConnectionDetails[NumberOfConnections]));

                    sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionType, sizeof(ConnectionDetails[NumberOfConnections].ConnectionType) - 1, "IPv6");

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

                    GetProcessNameFromPID((DWORD)pTcpTable->table[i].dwOwningPid, ConnectionDetails[NumberOfConnections].Process);
                    sprintf_s(ConnectionDetails[NumberOfConnections].PID, sizeof(ConnectionDetails[NumberOfConnections].PID) - 1, "%d ", (DWORD)pTcpTable->table[i].dwOwningPid);

                    if (InetNtop(AF_INET6, &pTcpTable->table[i].LocalAddr, ipstringbuffer, 46) == NULL) {
                        fprintf(stderr,"  InetNtop function failed for local IPv6 address\n");
                    } else {
                        to_narrow(ipstringbuffer, buffer, sizeof(buffer) - 1);
                        sprintf_s(ConnectionDetails[NumberOfConnections].LocalAddress, sizeof(ConnectionDetails[NumberOfConnections].LocalAddress) - 1, "%s", buffer);
                        if (config.ShowPortDescriptions == 1) {
                            strcat_s(ConnectionDetails[NumberOfConnections].LocalPort, sizeof(ConnectionDetails[NumberOfConnections].LocalPort) - 1, GetPortDescription(atoi(ConnectionDetails[NumberOfConnections].LocalPort)));
                        }

                    }                    
                    sprintf_s(ConnectionDetails[NumberOfConnections].LocalPort, sizeof(ConnectionDetails[NumberOfConnections].LocalPort) - 1,"%d", ntohs((u_short)pTcpTable->table[i].dwLocalPort));
                    
                    if (InetNtop(AF_INET6, &pTcpTable->table[i].RemoteAddr, ipstringbuffer, 46) != NULL) {
                        to_narrow(ipstringbuffer, buffer,sizeof(buffer) - 1);
                        sprintf_s(ConnectionDetails[NumberOfConnections].RemoteAddress, sizeof(ConnectionDetails[NumberOfConnections].RemoteAddress) - 1, "%s", buffer);
                    }                    
                    sprintf_s(ConnectionDetails[NumberOfConnections].RemotePort, sizeof(ConnectionDetails[NumberOfConnections].RemotePort) - 1, "%d ", ntohs((u_short)pTcpTable->table[i].dwRemotePort));
                    
                    strcat_s(ConnectionDetails[NumberOfConnections].RemotePort, sizeof(ConnectionDetails[NumberOfConnections].RemotePort) - 1, GetPortDescription(atoi(ConnectionDetails[NumberOfConnections].RemotePort)));
                
                    
                    // Only do the Reverse DNS if it's turned on and even then just do one lookup per call to this function, as it's a slow process.
                    if (config.DisableCountryLookup == 0 && COUNTRY_LOOKUP_DONE == 0) {
                        LookupRemoteIPDetails(ConnectionDetails[NumberOfConnections].RemoteAddress, &IP_Details, &COUNTRY_LOOKUP_DONE);
                        strcpy_s(ConnectionDetails[NumberOfConnections].Country, sizeof(ConnectionDetails[NumberOfConnections].Country) - 1, IP_Details.country);
                        strcpy_s(ConnectionDetails[NumberOfConnections].City, sizeof(ConnectionDetails[NumberOfConnections].City) - 1, IP_Details.city);
                        strcpy_s(ConnectionDetails[NumberOfConnections].ORG, sizeof(ConnectionDetails[NumberOfConnections].ORG) - 1, IP_Details.org);
                        strcpy_s(ConnectionDetails[NumberOfConnections].ISP, sizeof(ConnectionDetails[NumberOfConnections].ISP) - 1, IP_Details.isp);
                        strcpy_s(ConnectionDetails[NumberOfConnections].DOMAIN, sizeof(ConnectionDetails[NumberOfConnections].DOMAIN) - 1, IP_Details.domain);
                        strcpy_s(ConnectionDetails[NumberOfConnections].Description, sizeof(ConnectionDetails[NumberOfConnections].Description) - 1, IP_Details.description);
                    }
                    
                    
                    NumberOfConnections++;
                }
            }
        }
        else {
            fprintf(stderr,"\tGetTcp6Table failed with %d\n", dwRetVal);
            FREE(pTcpTable);
            return 1;
        }

        if (pTcpTable != NULL) {
            FREE(pTcpTable);
            pTcpTable = NULL;
        }

        return 0;    
}



/*---------------------------------------------------------------------------------------
 * Function: GetIPv4Connections
 * Get and process the IPv4 connection list.
 *
 * Parameters:
 * void.
 *
 * Returns:
 * 0 = No Errors, 1 = Error Occurred.
 * 
 * Notes:
 * Fills ConnectionDetails will the details on the IPv4 connections.
 * 
 ---------------------------------------------------------------------------------------*/
int GetIPv4Connections(void)
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
    int COUNTRY_LOOKUP_DONE = 0;
    char HostName[NI_MAXHOST] = { '\0' };
   
    if (config.HideIPv4 == 1) return 0;

    pTcpTable2 = (MIB_TCPTABLE2*)MALLOC(sizeof(MIB_TCPTABLE2));
    if (pTcpTable2 == NULL) {
        fprintf(stderr,"Error allocating memory\n");
        return 1;
    }

    ulSize = sizeof(MIB_TCPTABLE2);

    // Make an initial call to GetTcpTable to get the necessary size into the ulSize variable.
    if ((dwRetVal = GetTcpTable2(pTcpTable2, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
        FREE(pTcpTable2);
        pTcpTable2 = (MIB_TCPTABLE2*)MALLOC(ulSize);
        if (pTcpTable2 == NULL) {
            fprintf(stderr,"Error allocating memory\n");
            return 1;
        }
    }

    // Make a second call to GetTcpTable to get the actual data we require.
    if ((dwRetVal = GetTcpTable2(pTcpTable2, &ulSize, TRUE)) == NO_ERROR) {                
        for (i = 0; i < (int)pTcpTable2->dwNumEntries; i++) {
            if (FilterIPv4Entries(pTcpTable2, i) == 0) {
                
                ConnectionDetails = (ConnectionData*) realloc(ConnectionDetails, ((NumberOfConnections + 1) * sizeof(ConnectionData)));                
                if (ConnectionDetails == NULL) break;

                memset(&ConnectionDetails[NumberOfConnections], 0, sizeof(ConnectionDetails[NumberOfConnections]));

                // Process Name.
                GetProcessNameFromPID((DWORD)pTcpTable2->table[i].dwOwningPid, ConnectionDetails[NumberOfConnections].Process);

                // Display the Process PID.
                sprintf_s(ConnectionDetails[NumberOfConnections].PID, sizeof(ConnectionDetails[NumberOfConnections].PID) - 1, "%d", (DWORD)pTcpTable2->table[i].dwOwningPid);
                
                // Local address.
                IpAddr.S_un.S_addr = (u_long)pTcpTable2->table[i].dwLocalAddr;
                strcpy_s(ConnectionDetails[NumberOfConnections].LocalAddress, sizeof(ConnectionDetails[NumberOfConnections].LocalAddress) - 1, inet_ntoa(IpAddr));
                
                // Local port.
                sprintf_s(ConnectionDetails[NumberOfConnections].LocalPort, sizeof(ConnectionDetails[NumberOfConnections].LocalPort) - 1, "%d ", ntohs((u_short)pTcpTable2->table[i].dwLocalPort));
                if (config.ShowPortDescriptions == 1) {
                    strcat_s(ConnectionDetails[NumberOfConnections].LocalPort, sizeof(ConnectionDetails[NumberOfConnections].LocalPort) - 1, GetPortDescription(atoi(ConnectionDetails[NumberOfConnections].LocalPort)));
                }

                // Remote address.
                IpAddr.S_un.S_addr = (u_long)pTcpTable2->table[i].dwRemoteAddr;
                strcpy_s(ConnectionDetails[NumberOfConnections].RemoteAddress, sizeof(ConnectionDetails[NumberOfConnections].RemoteAddress) - 1, inet_ntoa(IpAddr));
                
                // Remote port.
                sprintf_s(ConnectionDetails[NumberOfConnections].RemotePort, sizeof(ConnectionDetails[NumberOfConnections].RemotePort) - 1,"%d ", ntohs((u_short)pTcpTable2->table[i].dwRemotePort));
                if (config.ShowPortDescriptions == 1) {
                    strcat_s(ConnectionDetails[NumberOfConnections].RemotePort, sizeof(ConnectionDetails[NumberOfConnections].RemotePort) - 1, GetPortDescription(atoi(ConnectionDetails[NumberOfConnections].RemotePort)));
                }

                // Only do the Reverse DNS if it's turned on and even then just do one lookup per call to this function, as it's a slow process.
                if (config.DisableCountryLookup == 0 && COUNTRY_LOOKUP_DONE == 0) {
                    LookupRemoteIPDetails(ConnectionDetails[NumberOfConnections].RemoteAddress, &IP_Details, &COUNTRY_LOOKUP_DONE);                    
                    strcpy_s(ConnectionDetails[NumberOfConnections].Country, sizeof(ConnectionDetails[NumberOfConnections].Country) - 1, IP_Details.country);
                    strcpy_s(ConnectionDetails[NumberOfConnections].City, sizeof(ConnectionDetails[NumberOfConnections].City) - 1, IP_Details.city);
                    strcpy_s(ConnectionDetails[NumberOfConnections].ORG, sizeof(ConnectionDetails[NumberOfConnections].ORG) - 1, IP_Details.org);
                    strcpy_s(ConnectionDetails[NumberOfConnections].ISP, sizeof(ConnectionDetails[NumberOfConnections].ISP) - 1, IP_Details.isp);
                    strcpy_s(ConnectionDetails[NumberOfConnections].DOMAIN, sizeof(ConnectionDetails[NumberOfConnections].DOMAIN) - 1, IP_Details.domain);
                    strcpy_s(ConnectionDetails[NumberOfConnections].Description, sizeof(ConnectionDetails[NumberOfConnections].Description) - 1, IP_Details.description);
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
                
                // Connection type IPv4 or IPv6
                sprintf_s(ConnectionDetails[NumberOfConnections].ConnectionType, sizeof(ConnectionDetails[NumberOfConnections].ConnectionType) - 1, "IPv4");
                NumberOfConnections++;
            }
        }
    } else {
        fprintf(stderr,"\tGetTcpTable failed with %d\n", dwRetVal);
        FREE(pTcpTable2);
        return 1;
    }

    if (pTcpTable2 != NULL) {
        FREE(pTcpTable2);
        pTcpTable2 = NULL;
        
    }

    return 0;
}



/*---------------------------------------------------------------------------------------
 * Function: GetPortDescription
 * Search the Port Descriptions and match the port number with it's description.
 *
 * Parameters:
 * int port - Port number to look up.
 *
 * Returns:
 * const char * Ports Description.
 *
 ---------------------------------------------------------------------------------------*/
const char* GetPortDescription(int port) {
    int low = 0;
    int high = 0;
    int median = 0;
    
    high = (sizeof(PortDescriptions) / sizeof(KeyValue));


    // Do a Binary search on the port description array.
    do {
        median = (low + high) / 2;
        if (port < PortDescriptions[median].key) {
            high = median - 1;
        }
        else {
            low = median + 1;
        }
    } while ((port != PortDescriptions[median].key) && low <= high);
  
    if (port ==  PortDescriptions[median].key) {
        return PortDescriptions[median].value;
    } else {
        return PortDescriptions[0].value;
    }
}



/*---------------------------------------------------------------------------------------
 * Function: cb_GridEnterCell
 * Called when the focus enters a cell.
 *
 * Parameters:
 * Ihandle* ih  - Handle to the control.
 * int lin      - Current Cell Line.
 * int col      - Current Cell Column.
 *
 * Returns:
 * IUP_DEFAULT
 *
 ---------------------------------------------------------------------------------------*/
int cb_GridEnterCell(Ihandle* ih, int lin, int col) {
    // Mark the selected line in the matrix.    
    IupSetAttributeId2(ih, "MARK", lin, 0, "1");
    return IUP_DEFAULT;
}



/*---------------------------------------------------------------------------------------
 * Function: cb_GridLeaveCell
 * Called when the focus leaves a cell.
 *
 * Parameters:
 * Ihandle* ih  - Handle to the control.
 * int lin      - Current Cell Line.
 * int col      - Current Cell Column.
 *
 * Returns:
 * IUP_DEFAULT
 *
 ---------------------------------------------------------------------------------------*/
int cb_GridLeaveCell(Ihandle* ih, int lin, int col) {
    // Unmark the selected line in the matrix.
    IupSetAttributeId2(ih, "MARK", lin, 0, "0");
    return IUP_DEFAULT;
}


/*---------------------------------------------------------------------------------------
 * Function: cb_GridValueChanged
 * Processes the Value Changed callback for the grid
 *
 * Parameters:
 * Ihandle* ih 	- Grids handle 
 *
 * Returns:
 * Nothing
 * 
 * Notes:
 * Updates the description field in the database with the new cell text.
 ---------------------------------------------------------------------------------------*/
int cb_GridValueChanged(Ihandle* ih) {
    char buffer[1024] = { '\0' };
    char SQL[1024] = { '\0' };
    sqlite3_stmt* stmt = NULL;
    sqlite3* DataBaseHandle;
    	
	// Find the database
    SHGetFolderPathA(0, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, buffer);
    strcat_s(buffer, sizeof(buffer) - 1, "\\Network_Status.db3");

	// Open the database
    sqlite3_open(buffer, &DataBaseHandle);

	// Update the description field for the selected remote IP.
    sprintf_s(SQL,sizeof(SQL) - 1, "UPDATE tblKnownIPs SET DESCRIPTION = '%s' WHERE IP = '%s';", IupGetAttributeId2(iGrid, "", CurrentLine, 8), IupGetAttributeId2(iGrid, "", CurrentLine, 6));    
    sqlite3_exec(DataBaseHandle, SQL, NULL, NULL, NULL);
    
	// Close the database
	sqlite3_close(DataBaseHandle);

	// Restart the timer.
    IupSetAttribute(iTimer, "RUN", "YES");
        
    return IUP_DEFAULT;
}



/*---------------------------------------------------------------------------------------
 * Function: cb_mnuaboutbox
 * Show the applications about box.
 *
 * Parameters:
 * void.
 *
 * Returns:
 * void.
 * 
 ---------------------------------------------------------------------------------------*/
void cb_mnuAboutBox(void) {
    char buffer[2048];
    strcpy_s(buffer, sizeof(buffer) - 1, "Network Status by Les Farrell");
    strcat_s(buffer, sizeof(buffer) - 1, "\n\nSQLite3 : \t\t");
    strcat_s(buffer, sizeof(buffer) - 1, sqlite3_version);
    strcat_s(buffer, sizeof(buffer) - 1, "\nIUP GUI Toolkit :\t");
    strcat_s(buffer, sizeof(buffer) - 1, IupGetGlobal("VERSION"));    
    strcat_s(buffer, sizeof(buffer) - 1, "\n\nCopyright 2022 Les Farrell");
    strcat_s(buffer, sizeof(buffer) - 1, "\nLast compiled at ");
    strcat_s(buffer, sizeof(buffer) - 1, __TIME__);
    strcat_s(buffer, sizeof(buffer) - 1, " on ");
    strcat_s(buffer, sizeof(buffer) - 1, __DATE__);
    IupMessage("About", buffer);
    return;
}



/*---------------------------------------------------------------------------------------
 * Function: cb_TimerTriggered
 * Call back function for the IUP timer.
 *
 * Parameters:
 * Ihandle *ih - Control handle.
 *
 * Returns:
 * IUP_DEFAULT
 *
 ---------------------------------------------------------------------------------------*/
int cb_TimerTriggered(Ihandle *ih) {

    NumberOfConnections = 0;

    // Grab the IPv4 connections.
    GetIPv4Connections();

    // Grab the IPv6 connections.
    GetIPv6Connections();

    // Fill the grid with connection details.
    FillNetworkStatusGrid();
    return IUP_DEFAULT;
}



/*---------------------------------------------------------------------------------------
 * Function: cb_mnuExit
 * Tells IUP to close down.
 *
 * Parameters:
 * void.
 *
 * Returns:
 * IUP_CLOSE
 *
 ---------------------------------------------------------------------------------------*/
int cb_mnuExit(void) {
  return IUP_CLOSE;
}


/*---------------------------------------------------------------------------------------
 * Function: cb_GridClickCell
 * Processes the click on cell callback.
 *
 * Parameters:
 * Ihandle* ih 	- Grids handle 
 * int lin		- Grid Line Clicked
 * int col, 	- Grid Column Clicked
 * char* status - Mouse Status
 *
 * Returns:
 * Nothing
 * 
 ---------------------------------------------------------------------------------------*/
int cb_GridClickCell(Ihandle* ih, int lin, int col, char* status)
{
	// If this is the first line then process the column sort routines.
    if (lin == 0)
    {             
		// Clicked on the same column twice so reverse the sort
        if (col == SortColumn)
        {
            if (SortDirection == 1) SortDirection = 0; else SortDirection = 1;            
        }
		// Sort the current column
        SortColumn = col;
		
		// Tell Iup to sort on this column.
        IupSetAttributeId(ih, "SORTCOLUMN", SortColumn, "ALL");
		
		// Refill the Grid
        FillNetworkStatusGrid();
		
        return IUP_DEFAULT;
    }

	// Has the Description column been clicked
    if (lin > 0 && col == 8)
    {   
		// Store the current Line.
        CurrentLine = lin;
		
		// Store the current remote IP address for this line.
        strcpy_s(CurrentIP, sizeof(CurrentIP) - 1, (char *) IupGetAttributeId2(iGrid, "", lin, 6));
        
        // Stop the timer.
        IupSetAttribute(iTimer, "RUN", "NO");
		
		// Edit the column as text.
        IupSetAttribute(iGrid, "TYPE*:8", "TEXT");
        
		// Make sure we can edit the grid.
		IupSetAttribute(iGrid, "READONLY", "NO");
		
		// Enter Edit mode.
        IupSetAttribute(iGrid, "EDITMODE", "YES");
    }	
    else
    {
		// Restart the timer
		IupSetAttribute(iTimer, "RUN", "YES");
		
		// Make the grid readonly again.
        IupSetAttribute(iGrid, "READONLY", "YES");
		
		// Start editing.
        IupSetAttribute(iGrid, "EDITMODE", "NO");
    }
    
    return IUP_DEFAULT;
    
}


/*---------------------------------------------------------------------------------------
 * Function: cb_mnuSettings
 * Show the settings dialog and apply the settings
 *
 * Parameters:
 *  void
 *
 * Returns:
 *  void
 ---------------------------------------------------------------------------------------*/
void cb_mnuSettings(void) {
    int result;
   
    LoadApplicationsSettings();

    // Build up the dialog and show it.
    result = IupGetParam("Settings", NULL, 0,
        "Hide IPv4 Connections : %b\n"
        "Hide IPv6 Connections : %b\n"
        "Hide 127.0.0.0 / 0.0.0.0 Connections : %b\n"
        "Disable IP Country Lookups : %b\n"
        "Hide Remote IP Description Column: %b\n"
        "Update Grid Every Secs: %i\n" 
        "Show Port Usage Descriptions: %b\n"
        "Filter by Port Numbers : %b\n"
        "Port Filter List (Separated by commas) : %s\n"
        "Country Lookup Server : %s\n",
        &config.HideIPv4,
        &config.HideIPv6,
        &config.HideLocalConections,
        &config.DisableCountryLookup, 
        &config.HideDescriptionColumn,
        &config.GridTimer,        
        &config.ShowPortDescriptions, 
        &config.ApplyPortFilter,
        &config.PortFilter,
        &config.WhoIs
    );
    
    // Okay was pressed so save the settings and refill the grid.
    if (result == 1) {
        SaveApplicationsSettings();

        NumberOfConnections = 0;

        // Grab the IPv4 connections.
        GetIPv4Connections();

        // Grab the IPv6 connections.
        GetIPv6Connections();

        // Fill the grid with connection details.
        FillNetworkStatusGrid();        
    }
    return;
}



/*---------------------------------------------------------------------------------------
 * Function: ApplyApplicationsSettings
 * Apply the settings from the configuration file.
 *
 * Parameters:
 *  void.
 *
 * Returns:
 *  void.
 *
 ---------------------------------------------------------------------------------------*/
void ApplyApplicationsSettings(void)
{
    
    if (config.HideDescriptionColumn == 1)
    {
        IupSetAttribute(iGrid, "WIDTH8", "0");
    }
    else
    {
        IupSetAttribute(iGrid, "WIDTH8", "120");
    }
    

    if (config.DisableCountryLookup == 1)
    {
        IupSetAttribute(iGrid, "WIDTH9", "0");
        IupSetAttribute(iGrid, "WIDTH10", "0");
        IupSetAttribute(iGrid, "WIDTH11", "0");
        IupSetAttribute(iGrid, "WIDTH12", "0");
        IupSetAttribute(iGrid, "WIDTH13", "0");
    }
    else
    {
        IupSetAttribute(iGrid, "WIDTH9", "95");
        IupSetAttribute(iGrid, "WIDTH10", "95");
        IupSetAttribute(iGrid, "WIDTH11", "120");
        IupSetAttribute(iGrid, "WIDTH12", "120");
        IupSetAttribute(iGrid, "WIDTH13", "120");
    }

    IupSetAttribute(iTimer, "RUN", "NO");
    IupSetCallback(iTimer, "ACTION_CB", (Icallback)cb_TimerTriggered);
    IupSetInt(iTimer, "TIME", config.GridTimer * 1000);
    IupSetAttribute(iTimer, "RUN", "YES");
    
}



/*---------------------------------------------------------------------------------------
 * Function: LoadApplicationsSettings
 * Load the settings from the configuration file.
 *
 * Parameters:
 *  void.
 *
 * Returns:
 *  void.
 *
 ---------------------------------------------------------------------------------------*/
void LoadApplicationsSettings(void) {    
    config.HideIPv4 = IupConfigGetVariableIntDef(iconfig, "NetStat", "HideIPv4", 0);
    config.HideIPv6 = IupConfigGetVariableIntDef(iconfig, "NetStat", "HideIPv6", 1);
    config.HideLocalConections = IupConfigGetVariableIntDef(iconfig, "NetStat", "HideLocal", 1);
    config.DisableCountryLookup = IupConfigGetVariableIntDef(iconfig, "NetStat", "DisableDNS", 0);
    config.ShowPortDescriptions = IupConfigGetVariableIntDef(iconfig, "NetStat", "ShowPortDescriptions", 0);       
    config.ApplyPortFilter = IupConfigGetVariableIntDef(iconfig, "NetStat", "ApplyPortFilter", 1);    
    config.HideDescriptionColumn = IupConfigGetVariableIntDef(iconfig, "NetStat", "HideDescriptionColumn", 0);
    strcpy_s(config.PortFilter, NI_MAXHOST, IupConfigGetVariableStrDef(iconfig, "NetStat", "PortFilter","\0"));
    strcpy_s(config.WhoIs, NI_MAXHOST, IupConfigGetVariableStrDef(iconfig, "NetStat", "LookupServer", "ipwho.is\0"));
    config.GridTimer = IupConfigGetVariableIntDef(iconfig, "NetStat", "GridTimer", 10);
    ApplyApplicationsSettings();
}



/*---------------------------------------------------------------------------------------
 * Function: SaveApplicationsSettings
 * Save the applications settings to the configuration file.
 *
 * Parameters:
 *  void.
 *
 * Returns:
 *  void.
 *
 ---------------------------------------------------------------------------------------*/
void SaveApplicationsSettings(void) {
    IupConfigSetVariableInt(iconfig, "NetStat", "HideIPv4", config.HideIPv4);
    IupConfigSetVariableInt(iconfig, "NetStat", "HideIPv6", config.HideIPv6);
    IupConfigSetVariableInt(iconfig, "NetStat", "HideLocal", config.HideLocalConections);
    IupConfigSetVariableInt(iconfig, "NetStat", "DisableDNS", config.DisableCountryLookup);
    IupConfigSetVariableInt(iconfig, "NetStat", "ShowPortDescriptions", config.ShowPortDescriptions);
    IupConfigSetVariableInt(iconfig, "NetStat", "ApplyPortFilter", config.ApplyPortFilter);
    IupConfigSetVariableStr(iconfig, "NetStat", "PortFilter", config.PortFilter);
    IupConfigSetVariableStr(iconfig, "NetStat", "LookupServer", config.WhoIs);    
    IupConfigSetVariableInt(iconfig, "NetStat", "HideDescriptionColumn", config.HideDescriptionColumn);    
    IupConfigSetVariableInt(iconfig, "NetStat", "GridTimer", config.GridTimer);
    
    IupConfigSave(iconfig);
    ApplyApplicationsSettings();
}



/*---------------------------------------------------------------------------------------
 * Function: to_narrow
 * Converts a wide character array to a char array for use in C strings.
 *
 * Parameters:
 * src  - Pointer to source wchar string.
 * dest - Pointer to destination char string.
 * dest_len - Size of the destination string array.
 *
 * Returns:
 *  Number of chars extracted from the wide char string.
 * 
 ---------------------------------------------------------------------------------------*/
size_t to_narrow(const wchar_t* src, char* dest, size_t dest_len) {
    size_t i = 0;
    wchar_t code;

    while (src[i] != '\0' && i < (dest_len - 1)) {
        code = src[i];
        if (code < 128)
            dest[i] = (char) code;
        else {
            dest[i] = '?';

            // lead surrogate, skip the next code unit, which is the trail.
            if (code >= 0xD800 && code <= 0xD8FF) {                
                i++;
            }
        }
        i++;
    }
    dest[i] = '\0';
    return i - 1;
}



/*---------------------------------------------------------------------------------------
 * Function: GetProcessNameFromPID
 * Finds the name of an executable given it's process ID.
 *
 * Parameters:
 * processID - PID of the process we are looking for.
 *
 * Returns:
 *  Fills 'szProcessName' with the executables name.
 * 
 ---------------------------------------------------------------------------------------*/
void GetProcessNameFromPID( DWORD processID, char* szProcessName) {
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
        if (Process32Next(hProcessSnap, &pe32) == 0) break;
	} 
    
    // Have we found a match?
    if (processID == pe32.th32ProcessID) {
        to_narrow(pe32.szExeFile, szProcessName, MAX_PATH);
    }
    else {
        // strcpy_s(szProcessName, sizeof(szProcessName) - 1, "<Unknown>");
    }

    // Must clean up the snapshot handle.
	CloseHandle( hProcessSnap );

	return;	
}



/*---------------------------------------------------------------------------------------
 * Function: FillNetworkStatusGrid
 * Fills a list with the connection details.
 *
 * Parameters:
 * None
 *
 * Returns:
 *  Status code
 * 
 ---------------------------------------------------------------------------------------*/
int FillNetworkStatusGrid() {
	int row = 0;
    static int lastcount = 0;

    // Set the number of visible lines in the grid.
    if (lastcount != NumberOfConnections) {
        IupSetInt(iGrid, "NUMLIN", NumberOfConnections );
        lastcount = NumberOfConnections;
    }

    // Loop and display each connection.
    for (row = 0; row <= NumberOfConnections; row++)
    {
        IupSetAttributeId2(iGrid, "", row + 1, 1, ConnectionDetails[row].Process);          // Process Name.
        IupSetAttributeId2(iGrid, "", row + 1, 2, ConnectionDetails[row].PID);              // Display the Process PID.        
        IupSetAttributeId2(iGrid, "", row + 1, 3, ConnectionDetails[row].ConnectionStatus); // Connection Status.
        IupSetAttributeId2(iGrid, "", row + 1, 4, ConnectionDetails[row].LocalAddress);     // Local address.      
        IupSetAttributeId2(iGrid, "", row + 1, 5, ConnectionDetails[row].LocalPort);        // Local port.
        IupSetAttributeId2(iGrid, "", row + 1, 6, ConnectionDetails[row].RemoteAddress);    // Remote address.
        IupSetAttributeId2(iGrid, "", row + 1, 7, ConnectionDetails[row].RemotePort);       // Remote port.                      
        IupSetAttributeId2(iGrid, "", row + 1, 8, ConnectionDetails[row].Description);      // Description.                
        IupSetAttributeId2(iGrid, "", row + 1, 9, ConnectionDetails[row].City);             // City.                
        IupSetAttributeId2(iGrid, "", row + 1, 10, ConnectionDetails[row].Country);         // Country.                
        IupSetAttributeId2(iGrid, "", row + 1, 11, ConnectionDetails[row].ISP);             // ISP
        IupSetAttributeId2(iGrid, "", row + 1, 12, ConnectionDetails[row].ORG);             // Org                
        IupSetAttributeId2(iGrid, "", row + 1, 13, ConnectionDetails[row].DOMAIN);          // Domain                
        IupSetAttributeId2(iGrid, "", row + 1, 14, ConnectionDetails[row].ConnectionType);  // Connection Type.        
    }
    
    IupSetAttributeId(iGrid, "SORTCOLUMN", SortColumn, "ALL");
    if (SortDirection == 0) {
        IupSetAttribute(iGrid, "SORTCOLUMNORDER", "ASCENDING");
    }
    else
    {
        IupSetAttribute(iGrid, "SORTCOLUMNORDER", "DESCENDING");
    }

    // Update the applications statusbar text.
    sprintf_s(sStatusBarText, sizeof(sStatusBarText) - 1, "Number of Entries : %d", NumberOfConnections);
    IupSetAttribute(iStatusbar, "TITLE", sStatusBarText);

    return 0;
}



/*---------------------------------------------------------------------------------------
 * Function: LookupRemoteIPDetails
 * lookup details for the passed IP address.
 *
 * Notes:
 * First checks the database and if nothing is found or the data is stale performs a country lookup.
 * And processes the returned JSON.
 * 
 * Parameters:
 *      IP - String containing the remote IP address.
 *
 * Returns:
 *      Status code
 * 
 ---------------------------------------------------------------------------------------*/
int LookupRemoteIPDetails(char * IP, IPDetails_struct* IP_Details, int *COUNTRY_LOOKUP_DONE) {    
    int Found = 0;
    char *strJSON = NULL;
    char buffer[1024] = { '\0' };
    char SQL[4096] = { '\0' };
    int rc = 0;
    sqlite3_stmt* stmtIPDetails;
    sqlite3* DataBaseHandle;

    memset(IP_Details, 0, sizeof(*IP_Details));
    
    Found = SearchDatabaseForIPDetails(IP, IP_Details);
    if (Found == 1) {
        *COUNTRY_LOOKUP_DONE = 0;
        return 0;
    }
    
    strcpy_s(buffer,sizeof(buffer) - 1, "/");
    strcat_s(buffer,sizeof(buffer) - 1, IP);

    strJSON = HTTP_GetContent(config.WhoIs, buffer);
    if (strJSON != NULL)
    {
        cJSON* json = cJSON_Parse(strJSON);

        const cJSON* ip = cJSON_GetObjectItemCaseSensitive(json, "ip");        
        const cJSON* success = cJSON_GetObjectItemCaseSensitive(json, "success");

        SHGetFolderPathA(0, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, buffer);
        strcat_s(buffer, sizeof(buffer) - 1, "\\Network_Status.db3");

        sqlite3_open(buffer, &DataBaseHandle);

        if (success->valueint == 1) {
            const cJSON* country = cJSON_GetObjectItemCaseSensitive(json, "country");
            const cJSON* city = cJSON_GetObjectItemCaseSensitive(json, "city");
            const cJSON* longitude = cJSON_GetObjectItemCaseSensitive(json, "longitude");
            const cJSON* latitude = cJSON_GetObjectItemCaseSensitive(json, "latitude");
            const cJSON* connection = cJSON_GetObjectItemCaseSensitive(json, "connection");
            const cJSON* org = cJSON_GetObjectItemCaseSensitive(connection, "org");
            const cJSON* isp = cJSON_GetObjectItemCaseSensitive(connection, "isp");
            const cJSON* domain = cJSON_GetObjectItemCaseSensitive(connection, "domain");

            sprintf_s(SQL, sizeof(SQL) - 1, "INSERT INTO tblKnownIPs (IP, Country, City, ORG, ISP, Domain, Latitude, Longitude) VALUES (?,?,?,?,?,?,?,?)");
            sqlite3_prepare_v2(DataBaseHandle, SQL, -1, &stmtIPDetails, 0);

            sqlite3_reset(stmtIPDetails);
            sqlite3_clear_bindings(stmtIPDetails);
            sqlite3_bind_text(stmtIPDetails, 1, ip->valuestring, -1, NULL);
            sqlite3_bind_text(stmtIPDetails, 2, country->valuestring, -1, NULL);
            sqlite3_bind_text(stmtIPDetails, 3, city->valuestring, -1, NULL);
            sqlite3_bind_text(stmtIPDetails, 4, org->valuestring, -1, NULL);
            sqlite3_bind_text(stmtIPDetails, 5, isp->valuestring, -1, NULL);
            sqlite3_bind_text(stmtIPDetails, 6, domain->valuestring, -1, NULL);
            sqlite3_bind_double(stmtIPDetails, 7, latitude->valuedouble);
            sqlite3_bind_double(stmtIPDetails, 8, longitude->valuedouble);

            rc = sqlite3_step(stmtIPDetails);
            if (rc != SQLITE_DONE) fprintf(stderr, "%s\n", sqlite3_errmsg(DataBaseHandle));

            // Finalise the statement.
            sqlite3_finalize(stmtIPDetails);

            memcpy(IP_Details->IP, ip->valuestring, sizeof(IP_Details->IP));
            memcpy(IP_Details->country, country->valuestring, sizeof(IP_Details->country));            
            memcpy(IP_Details->city,  city->valuestring,sizeof(IP_Details->city));
            memcpy(IP_Details->org, org->valuestring, sizeof(IP_Details->org));
            memcpy(IP_Details->isp, isp->valuestring, sizeof(IP_Details->isp));
            memcpy(IP_Details->domain, domain->valuestring, sizeof(IP_Details->domain));
        
        }
        else if (success->valueint == 0) 
        {

            const cJSON* message = cJSON_GetObjectItemCaseSensitive(json, "message");
            sprintf_s(SQL, sizeof(SQL) - 1, "INSERT INTO tblKnownIPs (IP, Country, City, ORG, ISP, Domain, Latitude, Longitude) VALUES (?,?,?,?,?,?,?,?)");
            sqlite3_prepare_v2(DataBaseHandle, SQL, -1, &stmtIPDetails, 0);

            sqlite3_reset(stmtIPDetails);
            sqlite3_clear_bindings(stmtIPDetails);
            sqlite3_bind_text(stmtIPDetails, 1, ip->valuestring, -1, NULL);
            sqlite3_bind_text(stmtIPDetails, 2, message->valuestring, -1, NULL);
            sqlite3_bind_text(stmtIPDetails, 3, message->valuestring, -1, NULL);
            sqlite3_bind_text(stmtIPDetails, 4, message->valuestring, -1, NULL);
            sqlite3_bind_text(stmtIPDetails, 5, message->valuestring, -1, NULL);
            sqlite3_bind_text(stmtIPDetails, 6, message->valuestring, -1, NULL);
            sqlite3_bind_double(stmtIPDetails, 7, 91.00);
            sqlite3_bind_double(stmtIPDetails, 8, 181.00);

            rc = sqlite3_step(stmtIPDetails);
            if (rc != SQLITE_DONE) fprintf(stderr, "%s\n", sqlite3_errmsg(DataBaseHandle));

            // Finalise the statement.
            sqlite3_finalize(stmtIPDetails);

            memcpy(IP_Details->IP, ip->valuestring, sizeof(IP_Details->IP));
            memcpy(IP_Details->country, message->valuestring, sizeof(IP_Details->country));
            memcpy(IP_Details->city, message->valuestring, sizeof(IP_Details->city));
            memcpy(IP_Details->org, message->valuestring, sizeof(IP_Details->org));
            memcpy(IP_Details->isp, message->valuestring, sizeof(IP_Details->isp));
            memcpy(IP_Details->domain, message->valuestring, sizeof(IP_Details->domain));
        }

        // Close the database
        sqlite3_close(DataBaseHandle);

        if (strJSON != NULL) free(strJSON);

        cJSON_Delete(json);
        
        *COUNTRY_LOOKUP_DONE = 1;
    }
    
    return 0;    
}



/*---------------------------------------------------------------------------------------
 * Function: Initialise Winsock
 * Initialise the Winsock library.
 *
 * Parameters:
 * Nothing.
 *
 * Returns:
 *  1 = Failed to initialise WinSock, otherwise returns 0.
 * 
 ---------------------------------------------------------------------------------------*/
int InitialiseWinsock() {    
    int iResult = 0;

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr,"WSAStartup failed: %d\n", iResult);
        return 1;
    }
    return 0;
}



/*---------------------------------------------------------------------------------------
 * Function: FileExists
 * Checks to see if a file exists by trying to open it
 *
 * Parameters:
 * filename - Path to the file to check.
 *
 * Returns:
 * int  : 1 = The file exists, otherwise returns 0
 *
 ---------------------------------------------------------------------------------------*/
int FileExists(const char* filename)
{
    FILE* fp;
    errno_t err;

    err = fopen_s(&fp, filename, "r");
    if ( err == 0)
    {
        fclose(fp);
        return 1;
    }
    return 0;
}



/*---------------------------------------------------------------------------------------
 * Function: CreateDefaultDatabase
 * Creates a sqlite database to hold the applications settings
 *
 * Parameters:
 * void
 *
 * Returns:
 * void
 * 
 * Notes:
 * The database is created in the root of the users 'My Documents' folder.
 *
 ---------------------------------------------------------------------------------------*/
void CreateDefaultDatabase(void)
{
    int rc = 0;
    char SQL[1024] = { '\0' };
    char buffer[1024] = { '\0' };
    sqlite3* DataBaseHandle;

    // Build up the path to the database.
    SHGetFolderPathA(0, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, buffer);    
    strcat_s(buffer,sizeof(buffer) -1, "\\Network_Status.db3");

    // If the database file doesn't exist then create it.
    if (FileExists(buffer) == 0)
    {
        rc = sqlite3_open(buffer, &DataBaseHandle);

        strcpy_s(SQL, sizeof(SQL) - 1, "CREATE TABLE IF NOT EXISTS tblKnownIPs (LastUpdated DATETIME DEFAULT (datetime('now','localtime')), IP TEXT UNIQUE, Description TEXT, ReverseDNS TEXT, Country TEXT, City TEXT, ORG TEXT, ISP TEXT, Domain TEXT, Latitude REAL, Longitude REAL);");
        rc = sqlite3_exec(DataBaseHandle, SQL, NULL, NULL, NULL);

        strcpy_s(SQL, sizeof(SQL) - 1, "INSERT INTO tblKnownIPs (IP, Country, City, ORG, ISP, Domain) VALUES ('0.0.0.0', 'Unknown', 'Unknown', 'localhost', 'localhost', 'localhost');");
        rc = sqlite3_exec(DataBaseHandle, SQL, NULL, NULL, NULL);

        strcpy_s(SQL, sizeof(SQL) - 1, "INSERT INTO tblKnownIPs (IP, Country, City, ORG, ISP, Domain) VALUES ('127.0.0.1', 'Unknown', 'Unknown', 'localhost', 'localhost', 'localhost');");
        rc = sqlite3_exec(DataBaseHandle, SQL, NULL, NULL, NULL);
                   
        strcpy_s(SQL, sizeof(SQL) - 1, "CREATE TABLE IF NOT EXISTS  tblKownPorts(Port INT CONSTRAINT Port PRIMARY KEY ON CONFLICT REPLACE,, Description TEXT);");                
        sqlite3_exec(DataBaseHandle, SQL, NULL, NULL, NULL);        
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (0,'');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (7, '(ECHO)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (17, '(QOTD)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (20,'(FTP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (21, '(FTP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (22, '(SSH)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (23, '(TELNET)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (25, '(SMTP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (42, '(WINS)');",NULL, NULL, NULL);                
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (43, '(WHOIS)');",NULL, NULL, NULL);        
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (53, '(DNS)');", NULL, NULL, NULL);        
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (69, '(TFTP)');", NULL, NULL, NULL);        
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (79, '(FINGER)');", NULL, NULL, NULL);        
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (80, '(HTTP)');", NULL, NULL, NULL);        
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (107, '(RTELNET)')",NULL, NULL, NULL);        
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (110, '(POP3)');", NULL, NULL, NULL);        
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (119, '(NNTP)');", NULL, NULL, NULL);        
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (123, '(NTP)');", NULL, NULL, NULL);        
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (135, '(RPC)');", NULL, NULL, NULL);        
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (137, '(NETBIOS)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (138, '(NETBIOS)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (139, '(NETBIOS)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (143, '(IMAP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (152, '(IMAP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (161, '(SNMP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (162, '(SNMP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (389, '(LDAP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (443, '(HTTPS)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (444, '(SNPP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (445, '(SMB)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (502, '(MODBUS)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (520, '(RIP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (530, '(RPC)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (531, '(IRC)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (546, '(DCHP)');",NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (547, '(DCHP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (554, '(RTSP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (563, '(NNTP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (564, '(ORACLE)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (587, '(SMTP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (631, '(IPP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (636, '(LDAPS)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (639, '(MSDP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (647, '(DHCP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (802, '(MODBUS)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (853, '(DNS/TLS)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (1026, '(DCOM)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (1029, '(DCOM)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (1080, '(SOCKS)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (1194, '(OPENVPN)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (1234, '(VLC)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (1883, '(MQTT)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (2732, '(STEAM)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (3306, '(MYSQL)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (3301, '(SAP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (4070, '(Spotify)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (5000, '(UPNP)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (5655, '(Remote Utilities)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (5800, '(VNC)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (5900, '(VNC)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (6000, '(X11)');", NULL, NULL, NULL);
        sqlite3_exec(DataBaseHandle, "INSERT INTO tblKnownPorts (Port , Description) Values (7680, '(Windows Update)');", NULL, NULL, NULL);

        rc = sqlite3_close_v2(DataBaseHandle);
    }
    
}



/*---------------------------------------------------------------------------------------
 * Function: SearchDatabaseForIPDetails
 * Search the database for details about the passed IP
 *
 * Parameters:
 * IP           - char * IP - IP Address to find.
 * IP_Details   - Pointer to IPDetails_struct.
 *
 * Returns:
 * 1 = Details found, otherwise returns 0.
 *
 ---------------------------------------------------------------------------------------*/
int SearchDatabaseForIPDetails(char* IP, IPDetails_struct* IP_Details)
{
    char buffer[1024] = { '\0' };
    char SQL[1024] = { '\0' };
    sqlite3_stmt* stmt = NULL;
    sqlite3* DataBaseHandle;
    int rc = 0;
    int Found = 0;

    SHGetFolderPathA(0, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, buffer);
    strcat_s(buffer,sizeof(buffer)-1,  "\\Network_Status.db3");

    rc = sqlite3_open(buffer, &DataBaseHandle);

    sprintf_s(SQL, sizeof(SQL) - 1, "SELECT IP, Country, City, latitude, longitude, org, isp, domain, description  FROM tblKnownIPs WHERE IP like '%s';", IP);

    rc = sqlite3_prepare_v2(DataBaseHandle, SQL, -1, &stmt, 0);
    if (rc == SQLITE_OK)
    {
        do
        {
            // Step for each record.
            rc = sqlite3_step(stmt);

            switch (rc)
            {
            case SQLITE_ROW:
                // Extract the data.
                sprintf_s(IP_Details->IP, sizeof(IP_Details->IP) - 1, "d%s", sqlite3_column_text(stmt, 0));
                sprintf_s(IP_Details->country, sizeof(IP_Details->country) - 1, "%s", sqlite3_column_text(stmt, 1));
                sprintf_s(IP_Details->city, sizeof(IP_Details->city) - 1, "%s", sqlite3_column_text(stmt, 2));
                IP_Details->latitude = sqlite3_column_double(stmt, 3);
                IP_Details->longitude = sqlite3_column_double(stmt, 4);
                sprintf_s(IP_Details->org, sizeof(IP_Details->org) - 1, "%s", sqlite3_column_text(stmt, 5));
                sprintf_s(IP_Details->isp, sizeof(IP_Details->isp) - 1, "%s", sqlite3_column_text(stmt, 6));
                sprintf_s(IP_Details->domain, sizeof(IP_Details->domain) - 1, "%s", sqlite3_column_text(stmt, 7));
                sprintf_s(IP_Details->description, sizeof(IP_Details->description) - 1, "%s", sqlite3_column_text(stmt, 8));
                if (strstr(IP_Details->description, "(null)")) IP_Details->description[0] = '\0';
                Found = 1;
                break;

            default:
                break;
            }

        } while (rc != SQLITE_DONE);
    }

    // Finalise the statement.
    sqlite3_finalize(stmt);

    rc = sqlite3_close_v2(DataBaseHandle);

    return Found;
}



/*---------------------------------------------------------------------------------------
 * Function: main
 * The programs main entry point.
 *
 * Parameters:
 * argc - Number of command line arguments.
 * argv - Array of command line strings.
 *
 * Returns:
 * Status Code
 * 
 ---------------------------------------------------------------------------------------*/
int main(int argc, char* argv[]) {
    Ihandle *iDialog;
    Ihandle *iVbox;
    
    Ihandle *file_menu, *item_exit;
    Ihandle *filesub_menu, *menu;
    Ihandle *options_menu, *item_settings;
    Ihandle *optionsub_menu;
    Ihandle *item_about;
    Ihandle *help_menu, *helpsub_menu;

    // Initialise the IUP toolkit.
    if (IupOpen(&argc, &argv) == IUP_ERROR) return 0;

    // Stop the Not Responding Message.
    IupSetGlobal("PROCESSWINDOWSGHOSTING", "NO");

    // Initialise IUP Controls.
    IupControlsOpen();

    // Initialise Winsock.
    InitialiseWinsock();

    // Create the SQLite database
    CreateDefaultDatabase();
        

    // Setup the file menu.
    item_exit = IupItem("Exit", NULL);
    IupSetCallback(item_exit, "ACTION", (Icallback) cb_mnuExit);
    file_menu = IupMenu(item_exit, NULL);
    filesub_menu = IupSubmenu("File", file_menu);

    // Setup the options menu.
    item_settings = IupItem("Settings", NULL);

    IupSetCallback(item_settings, "ACTION", (Icallback)cb_mnuSettings);
    options_menu = IupMenu(item_settings, NULL);
    optionsub_menu = IupSubmenu("Options", options_menu);

    // Setup the help menu.
    item_about = IupItem("About", NULL);
    help_menu = IupMenu(item_about, NULL);
    helpsub_menu = IupSubmenu("Help", help_menu);
    IupSetCallback(item_about, "ACTION", (Icallback)cb_mnuAboutBox);

    // Define the programs main menu.
    menu = IupMenu(filesub_menu, optionsub_menu, helpsub_menu, NULL);

    // Define the status bar.
    iStatusbar = IupFlatLabel("");
    IupSetAttribute(iStatusbar, "BORDER", "YES");

    // Define the matrix.
    iGrid = IupMatrixEx();

    // Grid attributes.
    IupSetAttribute(iGrid, "FLAT", "YES");
    IupSetAttribute(iGrid, "NUMCOL", "14");
    IupSetAttribute(iGrid, "EXPAND", "YES");
    IupSetAttribute(iGrid, "RESIZEMATRIX", "YES");
    IupSetAttribute(iGrid, "MARKMODE", "LIN");
    IupSetAttribute(iGrid, "READONLY", "NO");
    IupSetAttribute(iGrid, "MENUCONTEXT", "NO");
    IupSetAttribute(iGrid, "MARKMULTIPLE", "NO");
    IupSetAttribute(iGrid, "TYPE*:8", "TEXT");
    
    // Grid column titles, alignments and widths
    IupSetAttributeId2(iGrid, "", 0, 1, "Process");
    IupSetAttribute(iGrid, "WIDTH1", "115");
    IupSetAttribute(iGrid, "ALIGNMENT1", "ALEFT");

    IupSetAttributeId2(iGrid, "", 0, 2, "PID");
    IupSetAttribute(iGrid, "WIDTH2", "30");
    IupSetAttribute(iGrid, "ALIGNMENT2", "ALEFT");
    
    IupSetAttributeId2(iGrid, "", 0, 3, "Connection Status");
    IupSetAttribute(iGrid, "WIDTH3", "80");
    IupSetAttribute(iGrid, "ALIGNMENT3", "ALEFT");
    
    IupSetAttributeId2(iGrid, "", 0, 4, "Local Address");
    IupSetAttribute(iGrid, "WIDTH4", "75");
    IupSetAttribute(iGrid, "ALIGNMENT4", "ALEFT");

    IupSetAttributeId2(iGrid, "", 0, 5, "Local Port");
    IupSetAttribute(iGrid, "WIDTH5", "90");
    IupSetAttribute(iGrid, "ALIGNMENT5", "ALEFT");

    IupSetAttributeId2(iGrid, "", 0, 6, "Remote Address");
    IupSetAttribute(iGrid, "WIDTH6", "75");
    IupSetAttribute(iGrid, "ALIGNMENT6", "ALEFT");

    IupSetAttributeId2(iGrid, "", 0, 7, "Remote Port");    
    IupSetAttribute(iGrid, "WIDTH7", "90");
    IupSetAttribute(iGrid, "ALIGNMENT7", "ALEFT");
    
    IupSetAttributeId2(iGrid, "", 0, 8, "Description of Remote IP");
    IupSetAttribute(iGrid, "WIDTH8", "0");
    IupSetAttribute(iGrid, "ALIGNMENT8", "ALEFT");

    IupSetAttributeId2(iGrid, "", 0, 9, "City");
    IupSetAttribute(iGrid, "WIDTH9", "95");
    IupSetAttribute(iGrid, "ALIGNMENT9", "ALEFT");

    IupSetAttributeId2(iGrid, "", 0, 10, "Country");
    IupSetAttribute(iGrid, "WIDTH10", "95");
    IupSetAttribute(iGrid, "ALIGNMENT10", "ALEFT");

    IupSetAttributeId2(iGrid, "", 0, 11, "ISP");
    IupSetAttribute(iGrid, "WIDTH11", "120");
    IupSetAttribute(iGrid, "ALIGNMENT11", "ALEFT");

    IupSetAttributeId2(iGrid, "", 0, 12, "Organisation");    
    IupSetAttribute(iGrid, "WIDTH12", "120");
    IupSetAttribute(iGrid, "ALIGNMENT12", "ALEFT");

    IupSetAttributeId2(iGrid, "", 0, 13, "Domain");
    IupSetAttribute(iGrid, "WIDTH13", "120");
    IupSetAttribute(iGrid, "ALIGNMENT13", "ALEFT");

    IupSetAttributeId2(iGrid, "", 0, 14, "Type");
    IupSetAttribute(iGrid, "WIDTH14", "40");
    IupSetAttribute(iGrid, "ALIGNMENT14", "ALEFT");


    // Grid callbacks.
    IupSetCallback(iGrid, "ENTERITEM_CB", (Icallback)cb_GridEnterCell);
    IupSetCallback(iGrid, "LEAVEITEM_CB", (Icallback)cb_GridLeaveCell);
    IupSetCallback(iGrid, "CLICK_CB", (Icallback)cb_GridClickCell);
    IupSetCallback(iGrid, "VALUECHANGED_CB", (Icallback)cb_GridValueChanged);


    // Initialise dialog control layout.
    iVbox = IupVbox(iGrid, iStatusbar, NULL);
    IupSetAttribute(iVbox, "EXPAND", "YES");

    // Dialog attributes.
    iDialog = IupDialog(iVbox);
    IupSetAttributeHandle(iDialog, "MENU", menu);
    IupSetAttribute(iDialog, "SIZE", "745xHALF");
    IupSetAttribute(iDialog, "TITLE", "Network Status by Les Farrell");
    IupSetAttribute(iDialog, "SHRINK", "YES");
    IupSetAttribute(iDialog, "BACKGROUND", "255,128,255");
    

    // Status bar attributes.
    IupSetAttribute(iStatusbar, "NAME", "STATUSBAR");
    IupSetAttribute(iStatusbar, "EXPAND", "HORIZONTAL");
    IupSetAttribute(iStatusbar, "PADDING", "10x5");
    IupSetAttribute(iStatusbar, "TITLE", "Network Status - Copyright 2022 Les Farrell");

    // Initialise Configuration system.
    iconfig = IupConfig();
    IupSetAttribute(iconfig, "APP_NAME", "NetStat");

    
    // Load the configuration settings.
    IupConfigLoad(iconfig);
    LoadApplicationsSettings();


    // Timer attributes.
    iTimer = IupTimer();
    IupSetInt(iTimer, "TIME", config.GridTimer * 1000);   
    IupSetCallback(iTimer, "ACTION_CB", (Icallback)cb_TimerTriggered);
    IupSetAttribute(iTimer, "RUN", "YES");


    // Show the main dialog.
    IupShow(iDialog);

    // Grab the IPv4 connections.
    GetIPv4Connections();

    // Grab the IPv6 connections.
    GetIPv6Connections();

    // Fill the tcp details.
    FillNetworkStatusGrid();    

    
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

    // Free the connectiondetails array.
    if (ConnectionDetails != NULL) free(ConnectionDetails);

    // Close down the IUP toolkit.
    IupClose();

    // Close down Winsock.
    WSACleanup();

    return 0;
}

