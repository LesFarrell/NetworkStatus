#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <Iphlpapi.h>
#include <Tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "iup.h"
#include "iupcontrols.h"
#include "uthash.h"


// Function protypes
int FillNetStatGrid();
void FindProcessName( DWORD processID);
int ReverseDNSLookup(char* IP);
int InitialiseWinsock();
int timer_cb(Ihandle *ih);
size_t to_narrow(const wchar_t* src, char* dest, size_t dest_len);


char sStatusBarText[256];
char szProcessName[MAX_PATH] = {"<unknown>"};

Ihandle *iStatusbar;
Ihandle *iGrid;


// Hash structure for saving hostnames
struct  hostname_struct{
    char IP[32];
    char hostname[NI_MAXHOST];
    UT_hash_handle hh;
};
struct hostname_struct *reverseDNS_Hash = NULL, *DNS_Result = NULL;
char hostname[NI_MAXHOST] = { '\0' };

/* Note: could also use malloc() and free() */
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define CALLOC(x) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))


//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

int timer_cb(Ihandle *ih)
{
  FillNetStatGrid();
  return IUP_DEFAULT;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

int exit_cb(void)
{
  return IUP_CLOSE;
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
 * Number of chars extracted.
 */
size_t to_narrow(const wchar_t* src, char* dest, size_t dest_len) {
    size_t i;
    wchar_t code;

    i = 0;

    while (src[i] != '\0' && i < (dest_len - 1))
    {
        code = src[i];
        if (code < 128)
            dest[i] = (char) code;
        else
        {
            dest[i] = '?';
            if (code >= 0xD800 && code <= 0xD8FF)
            {
                // lead surrogate, skip the next code unit, which is the trail
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
 * Nothing
 */
void FindProcessName( DWORD processID)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
    
	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hProcessSnap == INVALID_HANDLE_VALUE )
	{
		return;
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof( PROCESSENTRY32 );

	// Retrieve information about the first process, and exit if unsuccessful
	if( !Process32First( hProcessSnap, &pe32 ) )
	{
        // Must clean up the snapshot handle.
        CloseHandle( hProcessSnap );    
		return;
	}

    // Search for the requested process ID
    while(processID != pe32.th32ProcessID)
	{
        Process32Next(hProcessSnap, &pe32);
	} 
    
    // Have we found a match?
    if (processID == pe32.th32ProcessID)
    {
        to_narrow(pe32.szExeFile, szProcessName, sizeof(szProcessName));
    }
    else
    {
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
int FillNetStatGrid()
{
    // Declare and initialize variables
    PMIB_TCPTABLE2 pTcpTable2;
    ULONG ulSize = 0;
    DWORD dwRetVal = 0;
    boolean DNS_LOOKUP = FALSE;

    char szLocalAddr[128] = { '\0' };
    char szRemoteAddr[128] = { '\0' };
    struct in_addr IpAddr;
    int i = 0;
    char buffer[256] = { '\0' };
    

    pTcpTable2 = (MIB_TCPTABLE2 *) MALLOC(sizeof(MIB_TCPTABLE2));
    if (pTcpTable2 == NULL) {
        printf("Error allocating memory\n");
        return 1;
    }

    ulSize = sizeof (MIB_TCPTABLE2);

    // Make an initial call to GetTcpTable to get the necessary size into the ulSize variable
    if ((dwRetVal = GetTcpTable2(pTcpTable2, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
        FREE(pTcpTable2);
        pTcpTable2 = (MIB_TCPTABLE2 *) MALLOC(ulSize);
        if (pTcpTable2 == NULL) {
            printf("Error allocating memory\n");
            return 1;
        }
    }

    // Make a second call to GetTcpTable to get the actual data we require
    if ((dwRetVal = GetTcpTable2(pTcpTable2, &ulSize, TRUE)) == NO_ERROR) {

        sprintf_s(buffer, sizeof(buffer) - 1, "%d", (int) pTcpTable2->dwNumEntries);
        IupSetAttribute(iGrid, "NUMLIN", buffer);

        sprintf_s(sStatusBarText, sizeof(sStatusBarText) - 1,  "Number of entries :%d   (* = Waiting for DNS lookup )", (int) pTcpTable2->dwNumEntries);
        IupSetAttribute(iStatusbar, "TITLE", (char *) sStatusBarText);

        for (i = 0; i < (int)pTcpTable2->dwNumEntries; i++) {

            // Process Name
            FindProcessName((DWORD)pTcpTable2->table[i].dwOwningPid);
            IupSetAttributeId2(iGrid, "", i + 1, 1, szProcessName);

            // Local address
            IpAddr.S_un.S_addr = (u_long)pTcpTable2->table[i].dwLocalAddr;
            strcpy_s(szLocalAddr, sizeof(szLocalAddr) - 1, inet_ntoa(IpAddr));
            IupSetAttributeId2(iGrid, "", i + 1, 2, szLocalAddr);

            // Local port
            sprintf_s(buffer, sizeof(buffer) - 1, "%d", ntohs((u_short)pTcpTable2->table[i].dwLocalPort));
            IupSetAttributeId2(iGrid, "", i + 1, 3, buffer);

            // Remote address
            IpAddr.S_un.S_addr = (u_long)pTcpTable2->table[i].dwRemoteAddr;
            strcpy_s(szRemoteAddr, sizeof(szRemoteAddr) - 1, inet_ntoa(IpAddr));
            IupSetAttributeId2(iGrid, "", i + 1, 4, szRemoteAddr);

            // Remote port
            sprintf_s(buffer, sizeof(buffer) - 1, "%d", ntohs((u_short)pTcpTable2->table[i].dwRemotePort));
            IupSetAttributeId2(iGrid, "", i + 1, 5, buffer);


            // Search the hash table for this IP.
            HASH_FIND_STR(reverseDNS_Hash, szRemoteAddr, DNS_Result);

            // Do a Reverse DNS on the remote address if needed
            if (!DNS_Result) 
            {
                // Is the DNS_LOOKUP flag false if so then do the lookup
                if (DNS_LOOKUP == FALSE) {
                    DNS_LOOKUP = TRUE;
                    ReverseDNSLookup(szRemoteAddr);
                }
                else
                {
                    // Skipped the lookup so just add the remote address for the time being.
                    strcpy_s(hostname, sizeof(hostname) - 1, szRemoteAddr);
                    strcat_s(hostname, sizeof(hostname) - 1, "*");
                }
            }
            else {
                strcpy_s(hostname, sizeof(hostname) - 1, DNS_Result->hostname);
            }
            IupSetAttributeId2(iGrid, "", i + 1, 6, hostname);

            // Display Socket states
            switch (pTcpTable2->table[i].dwState) {

                case MIB_TCP_STATE_CLOSED:
                    IupSetAttributeId2(iGrid, "", i + 1, 7,  "CLOSED");
                    break;

                case MIB_TCP_STATE_LISTEN:
                    IupSetAttributeId2(iGrid, "", i + 1, 7, "LISTEN");
                    break;

                case MIB_TCP_STATE_SYN_SENT:
                    IupSetAttributeId2(iGrid, "", i + 1, 7,  "SYN-SENT");
                    break;

                case MIB_TCP_STATE_SYN_RCVD:
                    IupSetAttributeId2(iGrid, "", i + 1, 7,  "SYN-RECIVED");
                    break;

                case MIB_TCP_STATE_ESTAB:
                    IupSetAttributeId2(iGrid, "", i + 1, 7,  "ESTABLISHED");
                    break;

                case MIB_TCP_STATE_FIN_WAIT1:
                    IupSetAttributeId2(iGrid, "", i + 1, 7,  "FIN-WAIT1");
                    break;

                case MIB_TCP_STATE_FIN_WAIT2:
                    IupSetAttributeId2(iGrid, "", i + 1, 7, "FIN-WAIT2");
                    break;

                case MIB_TCP_STATE_CLOSE_WAIT:
                    IupSetAttributeId2(iGrid, "", i + 1, 7,  "CLOSE-WAIT");
                    break;

                case MIB_TCP_STATE_CLOSING:
                    IupSetAttributeId2(iGrid, "", i + 1, 7,  "CLOSING");
                    break;

                case MIB_TCP_STATE_LAST_ACK:
                    IupSetAttributeId2(iGrid, "", i + 1, 7,  "LAST-ACK");
                    break;

                case MIB_TCP_STATE_TIME_WAIT:
                    IupSetAttributeId2(iGrid, "", i + 1, 7,  "TIME-WAIT");
                    break;

                case MIB_TCP_STATE_DELETE_TCB:
                    IupSetAttributeId2(iGrid, "", i + 1, 7,  "DELETE-TCB");
                    break;

                default:
                    IupSetAttributeId2(iGrid, "", i + 1, 7,  "UNKNOWN");
                    break;
            }

			// Display the Process PID
			sprintf_s(buffer, sizeof(buffer) - 1, "%d", pTcpTable2->table[i].dwOwningPid);
			IupSetAttributeId2(iGrid, "", i + 1, 8, buffer);

        }
    } else {
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



/*
 * Function: ReverseDNSLookup
 * Tries to do a reverse lookup on the passed IP address
 *
 * Parameters:
 * IP - String containing the remote IP address
 *
 * Returns:
 * Status code
 */
int ReverseDNSLookup(char* IP)
{
    DWORD dwRetval;
    struct sockaddr_in saGNI;    
    char servInfo[NI_MAXSERV];
    u_short port = 27015;

    HASH_FIND_STR(reverseDNS_Hash, IP, DNS_Result);
    
    if (!DNS_Result)
    {
        // Set up sockaddr_in structure which is passed to the getnameinfo function
        saGNI.sin_family = AF_INET;
        saGNI.sin_addr.s_addr = inet_addr(IP);
        saGNI.sin_port = htons(port);

        // Call getnameinfo
        dwRetval = getnameinfo((struct sockaddr*)&saGNI, sizeof(struct sockaddr), hostname, NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);

        if (dwRetval != 0) {
            printf("getnameinfo failed with error # %ld\n", WSAGetLastError());
            return 1;
        }
        else {
            // Store the result in the hash table.
            DNS_Result = (struct hostname_struct *) MALLOC(sizeof * DNS_Result);
            strcpy_s(DNS_Result->IP, sizeof(DNS_Result->IP) - 1, IP);
            strcpy_s(DNS_Result->hostname,sizeof(DNS_Result->hostname) - 1, hostname);
            HASH_ADD_STR(reverseDNS_Hash, IP, DNS_Result);
            return 0;
        }
    }
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
int InitialiseWinsock()
{
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
 * Function: main
 * The programs main entry point
 *
 * Parameters:
 * argc - Number of command line arguments.
 * argv - Array of command line strings.
 *
 * Returns:
 * Status Code
 */
int main(int argc, char* argv[])
{
    Ihandle* iDialog;
    Ihandle* iVbox;
    Ihandle* iTimer;
    Ihandle* toolbar_hb, * btn_save, * btn_open, * btn_help;
    Ihandle* file_menu, * item_exit;
    Ihandle* filesub_menu, * menu;
    Ihandle* options_menu, * item_settings;
    Ihandle* optionsub_menu;
    
    struct hostname_struct* tmp = NULL;

    // Initialise IUP
    if (IupOpen(&argc, &argv) == IUP_ERROR) return 0;

    // Initialise IUP Controls
    IupControlsOpen();

    // Initialise IUP Image library
    IupImageLibOpen();

    //item_open = IupItem("Open", NULL);
    //item_saveas = IupItem("Save As", NULL);

    // Setup the file menu.
    item_exit = IupItem("Exit", NULL);
    IupSetCallback(item_exit, "ACTION", (Icallback)exit_cb);
    file_menu = IupMenu(
        IupSeparator(),
        item_exit,
        NULL);
    filesub_menu = IupSubmenu("File", file_menu);

    // Setup the options menu.
    item_settings = IupItem("Configuration", NULL);
    options_menu = IupMenu(
        item_settings,
        NULL);
    optionsub_menu = IupSubmenu("Options", options_menu);

    menu = IupMenu(filesub_menu, optionsub_menu, NULL);

    // Controls
    iStatusbar = IupLabel("");
    iGrid = IupMatrixEx();

    btn_open = IupButton(NULL, NULL);
    IupSetAttribute(btn_open, "IMAGE", "IUP_FileOpen");
    IupSetAttribute(btn_open, "FLAT", "Yes");
    IupSetAttribute(btn_open, "CANFOCUS", "No");

    btn_save = IupButton(NULL, NULL);
    IupSetAttribute(btn_save, "IMAGE", "IUP_FileSave");
    IupSetAttribute(btn_save, "FLAT", "Yes");
    IupSetAttribute(btn_save, "CANFOCUS", "No");

    btn_help = IupButton(NULL, NULL);
    IupSetAttribute(btn_help, "IMAGE", "IUP_MessageHelp");
    IupSetAttribute(btn_help, "FLAT", "Yes");
    IupSetAttribute(btn_help, "CANFOCUS", "No");

    toolbar_hb = IupHbox(
        btn_open,
        btn_save,
        IupSetAttributes(IupLabel(NULL), "SEPARATOR=VERTICAL"),
        btn_help,
        NULL);
    IupSetAttribute(toolbar_hb, "MARGIN", "5x5");
    IupSetAttribute(toolbar_hb, "GAP", "2");

    // Initialise dialog control layout
    iVbox = IupVbox(
        // toolbar_hb,
        iGrid,
        iStatusbar,
        NULL);

    // Dialog attributes
    iDialog = IupDialog(iVbox);
    IupSetAttributeHandle(iDialog, "MENU", menu);
    IupSetAttribute(iDialog, "SIZE", "HALFxHALF");
    IupSetAttribute(iDialog, "TITLE", "Network Status");

    // Grid attributes
    IupSetAttribute(iGrid, "NUMCOL", "8");
    IupSetAttribute(iGrid, "ALIGNMENT", "ALEFT");
    IupSetAttribute(iGrid, "EXPAND", "YES");
    IupSetAttribute(iGrid, "RESIZEMATRIX", "YES");
    IupSetAttribute(iGrid, "MARKMODE", "LIN");
    IupSetAttribute(iGrid, "READONLY", "YES");

    // Grid column titles
    IupSetAttributeId2(iGrid, "", 0, 1, "Process");
    IupSetAttributeId2(iGrid, "", 0, 2, "Local Address");
    IupSetAttributeId2(iGrid, "", 0, 3, "Local Port");
    IupSetAttributeId2(iGrid, "", 0, 4, "Remote Address");
    IupSetAttributeId2(iGrid, "", 0, 5, "Remote Port");
    IupSetAttributeId2(iGrid, "", 0, 6, "Reverse DNS");
    IupSetAttributeId2(iGrid, "", 0, 7, "Connection Status");
    IupSetAttributeId2(iGrid, "", 0, 8, "PID");

    // Timer attributes
    iTimer = IupTimer();
    IupSetAttribute(iTimer, "TIME", "2000");
    IupSetAttribute(iTimer, "RUN", "YES");
    IupSetCallback(iTimer, "ACTION_CB", (Icallback)timer_cb);

    // Status bar attributes
    IupSetAttribute(iStatusbar, "NAME", "STATUSBAR");
    IupSetAttribute(iStatusbar, "EXPAND", "HORIZONTAL");
    IupSetAttribute(iStatusbar, "PADDING", "10x5");

    // Show the main dialog
    IupShow(iDialog);

    // Initialise Winsock
    InitialiseWinsock();

    // Fill the tcp details
    FillNetStatGrid();

    // IUP main loop
    IupMainLoop();

    // Detroy the IUP controls
    IupDestroy(iGrid);
    IupDestroy(iVbox);
    IupDestroy(iTimer);
    IupDestroy(iStatusbar);
    IupDestroy(iDialog);
    IupClose();

    /* free the DNS hash table contents */
    HASH_ITER(hh, reverseDNS_Hash, DNS_Result, tmp) {
        HASH_DEL(reverseDNS_Hash, DNS_Result);
        FREE(DNS_Result);
    }

    return 0;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
