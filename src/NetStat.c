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
char szProcessName[MAX_PATH] = {"<unknown>"};
Ihandle *iStatusbar;
Ihandle *iGrid;
Ihandle *iconfig;


/* Note: could also use malloc() and free() */
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define CALLOC(x) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

int cb_EnterCell(Ihandle* ih, int lin, int col)
{
    IupSetAttributeId2(ih, "MARK", lin, 0, "1");
    return IUP_DEFAULT;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

int cb_LeaveCell(Ihandle* ih, int lin, int col)
{
    IupSetAttributeId2(ih, "MARK", lin, 0, "0");
    return IUP_DEFAULT;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/*
 * Function: mnuaboutbox_cb
 * Show the applications about box.
 *
 * Parameters:
 * None.
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
        "Hide connections to 127.0.0.0 / 0.0.0.0  : %b[No,Yes]\n"
        "Disable DNS Lookup  : %b[No,Yes]\n"
        , &config.HideLocalConections, &config.DisableDNSLookup);

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
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

void saveSettings(void) {
    // Save the updated settings.
    IupConfigSetVariableInt(iconfig, "NetStat", "HideLocal", config.HideLocalConections);
    IupConfigSetVariableInt(iconfig, "NetStat", "DisableDNS", config.DisableDNSLookup);
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
            if (code >= 0xD800 && code <= 0xD8FF) {
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
 * void
 */
void FindProcessName( DWORD processID) {
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
        to_narrow(pe32.szExeFile, szProcessName, sizeof(szProcessName));
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
    int row = 0;
    

    pTcpTable2 = (MIB_TCPTABLE2 *) MALLOC(sizeof(MIB_TCPTABLE2));
    if (pTcpTable2 == NULL) {
        printf("Error allocating memory\n");
        return 1;
    }

    ulSize = sizeof (MIB_TCPTABLE2);

    // Make an initial call to GetTcpTable to get the necessary size into the ulSize variable.
    if ((dwRetVal = GetTcpTable2(pTcpTable2, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
        FREE(pTcpTable2);
        pTcpTable2 = (MIB_TCPTABLE2 *) MALLOC(ulSize);
        if (pTcpTable2 == NULL) {
            printf("Error allocating memory\n");
            return 1;
        }
    }

    // Make a second call to GetTcpTable to get the actual data we require.
    if ((dwRetVal = GetTcpTable2(pTcpTable2, &ulSize, TRUE)) == NO_ERROR) {

        row = 0;
        for (i = 0; i < (int)pTcpTable2->dwNumEntries; i++) {

            if (FilterEntry(pTcpTable2, i) == 0) {
                // Process Name.
                FindProcessName((DWORD)pTcpTable2->table[i].dwOwningPid);
                IupSetAttributeId2(iGrid, "", row + 1, 1, szProcessName);

                // Local address.
                IpAddr.S_un.S_addr = (u_long)pTcpTable2->table[i].dwLocalAddr;
                strcpy_s(szLocalAddr, sizeof(szLocalAddr) - 1, inet_ntoa(IpAddr));
                IupSetAttributeId2(iGrid, "", row + 1, 2, szLocalAddr);

                // Local port.
                sprintf_s(buffer, sizeof(buffer) - 1, "%d", ntohs((u_short)pTcpTable2->table[i].dwLocalPort));
                IupSetAttributeId2(iGrid, "", row + 1, 3, buffer);

                // Remote address.
                IpAddr.S_un.S_addr = (u_long)pTcpTable2->table[i].dwRemoteAddr;
                strcpy_s(szRemoteAddr, sizeof(szRemoteAddr) - 1, inet_ntoa(IpAddr));
                IupSetAttributeId2(iGrid, "", row + 1, 4, szRemoteAddr);

                // Remote port.
                sprintf_s(buffer, sizeof(buffer) - 1, "%d", ntohs((u_short)pTcpTable2->table[i].dwRemotePort));
                IupSetAttributeId2(iGrid, "", row + 1, 5, buffer);

                // Search the hash table for this IP.
                HASH_FIND_STR(reverseDNS_Hash, szRemoteAddr, DNS_Result);

                // Do a Reverse DNS on the remote address if needed.
                
                 // Just add the remote address for the time being.
                strcpy_s(hostname, sizeof(hostname) - 1, szRemoteAddr);
                strcat_s(hostname, sizeof(hostname) - 1, "*");

                if (config.DisableDNSLookup == 0) {
                    if (!DNS_Result) {
                        // Is the DNS_LOOKUP flag false if so then do the lookup.
                        if (DNS_LOOKUP == FALSE) {
                            DNS_LOOKUP = TRUE;
                            ReverseDNSLookup(szRemoteAddr);
                        }
                    }
                    else {
                        strcpy_s(hostname, sizeof(hostname) - 1, DNS_Result->hostname);
                    }
                }
                IupSetAttributeId2(iGrid, "", row + 1, 6, hostname);

                // Display Socket states.
                switch (pTcpTable2->table[i].dwState) {

                    case MIB_TCP_STATE_CLOSED:
                        IupSetAttributeId2(iGrid, "", row + 1, 7,  "CLOSED");
                        break;

                    case MIB_TCP_STATE_LISTEN:
                        IupSetAttributeId2(iGrid, "", row + 1, 7, "LISTEN");
                        break;

                    case MIB_TCP_STATE_SYN_SENT:
                        IupSetAttributeId2(iGrid, "", row + 1, 7,  "SYN-SENT");
                        break;

                    case MIB_TCP_STATE_SYN_RCVD:
                        IupSetAttributeId2(iGrid, "", row + 1, 7,  "SYN-RECIVED");
                        break;

                    case MIB_TCP_STATE_ESTAB:
                        IupSetAttributeId2(iGrid, "", row + 1, 7,  "ESTABLISHED");
                        break;

                    case MIB_TCP_STATE_FIN_WAIT1:
                        IupSetAttributeId2(iGrid, "", row + 1, 7,  "FIN-WAIT1");
                        break;

                    case MIB_TCP_STATE_FIN_WAIT2:
                        IupSetAttributeId2(iGrid, "", row + 1, 7, "FIN-WAIT2");
                        break;

                    case MIB_TCP_STATE_CLOSE_WAIT:
                        IupSetAttributeId2(iGrid, "", row + 1, 7,  "CLOSE-WAIT");
                        break;

                    case MIB_TCP_STATE_CLOSING:
                        IupSetAttributeId2(iGrid, "", row + 1, 7,  "CLOSING");
                        break;

                    case MIB_TCP_STATE_LAST_ACK:
                        IupSetAttributeId2(iGrid, "", row + 1, 7,  "LAST-ACK");
                        break;

                    case MIB_TCP_STATE_TIME_WAIT:
                        IupSetAttributeId2(iGrid, "", row + 1, 7,  "TIME-WAIT");
                        break;

                    case MIB_TCP_STATE_DELETE_TCB:
                        IupSetAttributeId2(iGrid, "", row + 1, 7,  "DELETE-TCB");
                        break;

                    default:
                        IupSetAttributeId2(iGrid, "", row + 1, 7,  "UNKNOWN");
                        break;
                }

    			// Display the Process PID.
    			// sprintf_s(buffer, sizeof(buffer) - 1, "%d", pTcpTable2->table[i].dwOwningPid);
    			// IupSetAttributeId2(iGrid, "", i + 1, 8, buffer);

                row++;
            }            

        }
        if (config.DisableDNSLookup == 0) {
            sprintf_s(sStatusBarText, sizeof(sStatusBarText) - 1, "Number of entries : %d  (* Awaiting DNS result)", (int)pTcpTable2->dwNumEntries - row);
        }
        else {
            sprintf_s(sStatusBarText, sizeof(sStatusBarText) - 1, "Number of entries : %d  (* DNS Lookup Disabled)", (int)pTcpTable2->dwNumEntries - row);
        }
        IupSetAttribute(iStatusbar, "TITLE", (char*)sStatusBarText);

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
 * Tries to do a reverse lookup on the passed IP address.
 *
 * Parameters:
 * IP - String containing the remote IP address.
 *
 * Returns:
 * Status code
 */
int ReverseDNSLookup(char* IP) {
    DWORD dwRetval;
    struct sockaddr_in saGNI;    
    char servInfo[NI_MAXSERV];
    u_short port = 27015;

    HASH_FIND_STR(reverseDNS_Hash, IP, DNS_Result);
    
    if (!DNS_Result) {
        // Set up sockaddr_in structure which is passed to the getnameinfo function.
        saGNI.sin_family = AF_INET;
        saGNI.sin_addr.s_addr = inet_addr(IP);
        saGNI.sin_port = htons(port);

        // Call getnameinfo.
        dwRetval = getnameinfo((struct sockaddr*)&saGNI, sizeof(struct sockaddr), hostname, NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);

        if (dwRetval != 0) {
            printf("getnameinfo failed with error # %ld\n", WSAGetLastError());
            return 1;
        }
        else {
            // Store the result in the hash table.
            DNS_Result = (struct hostname_struct *) malloc(sizeof * DNS_Result);
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
int FilterEntry(PMIB_TCPTABLE2 pTcpTable2, int ientry)
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

    struct hostname_struct* tmpDNS = NULL;

    // Initialise IUP.
    if (IupOpen(&argc, &argv) == IUP_ERROR) return 0;

    // Initialise IUP Controls.
    IupControlsOpen();

    // Initialise IUP Image library.
    // IupImageLibOpen();

    // Setup the file menu.
    item_exit = IupItem("Exit", NULL);
    IupSetCallback(item_exit, "ACTION", (Icallback)cb_mnuExit);
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

    // Define the main menu.
    menu = IupMenu(filesub_menu, optionsub_menu, helpsub_menu, NULL);

    // Controls.
    
    // Define the status bar.
    iStatusbar = IupLabel("");
    IupSetAttribute(iStatusbar, "PADDING", "10x5");

    // Define the matrix.
    iGrid = IupMatrixEx();
    

    // Initialise dialog control layout.
    iVbox = IupVbox(
        iGrid,
        iStatusbar,
        NULL);
    IupSetAttribute(iVbox, "EXPAND", "YES");

    
    // Dialog attributes.
    iDialog = IupDialog(iVbox);
    IupSetAttributeHandle(iDialog, "MENU", menu);
    IupSetAttribute(iDialog, "SIZE", "HALFxHALF");
    IupSetAttribute(iDialog, "TITLE", "Network Status");
    IupSetAttribute(iDialog, "SHRINK", "YES");
    IupSetAttribute(iDialog, "ICON", "network.ico");



    // Grid attributes.
    IupSetAttribute(iGrid, "FLAT", "YES");
    IupSetAttribute(iGrid, "NUMCOL", "7");
    IupSetAttribute(iGrid, "ALIGNMENT", "ALEFT");
    IupSetAttribute(iGrid, "EXPAND", "YES");
    IupSetAttribute(iGrid, "RESIZEMATRIX", "YES");
    IupSetAttribute(iGrid, "MARKMODE", "LIN");
    IupSetAttribute(iGrid, "READONLY", "YES");
    IupSetAttribute(iGrid, "MENUCONTEXT", "NO");
    IupSetAttribute(iGrid, "NUMLIN", "4096");

    // Grid callbacks.
    IupSetCallback(iGrid, "ENTERITEM_CB", (Icallback)cb_EnterCell);
    IupSetCallback(iGrid, "LEAVEITEM_CB", (Icallback)cb_LeaveCell);
    
    // Grid column titles.
    IupSetAttributeId2(iGrid, "", 0, 1, "Process");
    IupSetAttribute(iGrid, "WIDTH1", "100");

    IupSetAttributeId2(iGrid, "", 0, 2, "Local Address");
    IupSetAttribute(iGrid, "WIDTH2", "55");
    IupSetAttribute(iGrid, "ALIGNMENT2", "ACENTER");

    IupSetAttributeId2(iGrid, "", 0, 3, "Local Port");
    IupSetAttribute(iGrid, "WIDTH3", "55");
    IupSetAttribute(iGrid, "ALIGNMENT3", "ACENTER");

    IupSetAttributeId2(iGrid, "", 0, 4, "Remote Address");
    IupSetAttribute(iGrid, "WIDTH4", "60");
    IupSetAttribute(iGrid, "ALIGNMENT4", "ACENTER");

    IupSetAttributeId2(iGrid, "", 0, 5, "Remote Port");
    IupSetAttribute(iGrid, "WIDTH5", "55");
    IupSetAttribute(iGrid, "ALIGNMENT5", "ACENTER");

    IupSetAttributeId2(iGrid, "", 0, 6, "Reverse DNS");
    IupSetAttribute(iGrid, "WIDTH6", "155");

    IupSetAttributeId2(iGrid, "", 0, 7, "Connection Status");
    IupSetAttribute(iGrid, "WIDTH7", "90");
    IupSetAttribute(iGrid, "ALIGNMENT7", "ACENTER");
    
    

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

    // Initialise Winsock.
    InitialiseWinsock();

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

    // Save the current configuration
    IupConfigSave(iconfig);

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


