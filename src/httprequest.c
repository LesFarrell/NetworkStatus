#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "httprequest.h"

SOCKET conn;

/*---------------------------------------------------------------------------------------
 * Function: HTTP_GetContent
 * Connect to the passed host and requests the contents of 'path'
 *
 * Parameters:
 * Host : Host to the connect to.
 * Path : Path to the request.
 *
 * Returns:
 * The contents of the returned website.
 *
 *---------------------------------------------------------------------------------------*/
char *HTTP_GetContent(char *host, char *path) {
    char *HeaderBuffer = NULL;
    char *ContentBuffer = NULL;
    char *ResponseBuffer = NULL;
	long ContentLength = 0;
	char ReadBuffer[8096];
	char SendBuffer[8096];
    char* temp = NULL;
	long HeaderLength = 0;
    int BytesReceived = 0;
    int TotalBytesReceived = 0;   

    // Connect to the remote server
    conn = HTTP_ConnectToServer(host, 80);
    if (conn == 0) {
		// No Internet connection.
        return NULL;
	}

    // Send the request for data.
    sprintf_s(SendBuffer,sizeof(SendBuffer) -1, "GET %s HTTP/1.0 \r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
    send(conn, SendBuffer, strlen(SendBuffer), 0);

	while(1)
	{
        // Clear read buffer ready for more data.
        memset(ReadBuffer, 0, HTTP_BufferSize);

        // Read the Response into Read buffer.
		BytesReceived = recv(conn, ReadBuffer, HTTP_BufferSize, 0);

        // No further data so exit the loop.
        if ( BytesReceived <= 0 ) {
			break;
		}

        // Loop and keep adding the ReadBuffer to the ResponseBuffer
        temp = (char*) realloc(ResponseBuffer, (BytesReceived + TotalBytesReceived));
        if (temp != NULL) ResponseBuffer = temp;
        if ((ResponseBuffer + TotalBytesReceived) > 0) {
            memcpy((ResponseBuffer + TotalBytesReceived), ReadBuffer, BytesReceived);
        }

        // Increase the total number of bytes received so far.
        TotalBytesReceived += BytesReceived;
    }

    // Find the length of the header.
    HeaderLength = HTTP_GetHeaderLength(ResponseBuffer);

    // Grab the Content from the response buffer.
    ContentLength = TotalBytesReceived - HeaderLength;
    ContentBuffer = (char *) malloc(ContentLength + 1);
    if (ContentBuffer != NULL) {
        memcpy(ContentBuffer, (ResponseBuffer + HeaderLength), ContentLength);
    }
    if (ContentBuffer != NULL) ContentBuffer[ContentLength] = '\0';

    // Grab the header from the response buffer.
    HeaderBuffer = (char*)malloc(HeaderLength + 1);
    
    if (HeaderBuffer != NULL && HeaderLength > 0 && ResponseBuffer !=NULL) {
        memcpy(HeaderBuffer,  ResponseBuffer, HeaderLength );        
        if (HeaderBuffer != NULL) HeaderBuffer[HeaderLength] = '\0';
    }

    // Close the connection.
    closesocket(conn);

    // Clear the buffers.
    if (ResponseBuffer != NULL) free(ResponseBuffer);
	if (HeaderBuffer != NULL) free(HeaderBuffer);

    // Return the pointer to the ContentBuffer.
    return(ContentBuffer);
}


/*---------------------------------------------------------------------------------------
 * Function: HTTP_ConnectToServer
 * Connect to a server and port
 *
 * Parameters:
 * szServerName : URL of the server to connect to.
 * portNum : Port number to connect to.
 *
 * Returns:
 * The SOCKET connection.
 *
 *---------------------------------------------------------------------------------------*/
SOCKET HTTP_ConnectToServer(char *szServerName, WORD portNum) {
	struct sockaddr_in server;
	unsigned int addr;
	struct hostent *hp;

    conn = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (conn == INVALID_SOCKET) { return 0; }

    if (inet_addr(szServerName) == INADDR_NONE) {
		hp = gethostbyname(szServerName);
	} else {
        addr = inet_addr(szServerName);
        hp = gethostbyaddr( (char*) &addr, sizeof(addr), AF_INET);
    }

    if (hp == NULL ) {
		closesocket(conn);
		return 0;
	}

    server.sin_addr.s_addr = *((unsigned long*) hp->h_addr);
    server.sin_family = AF_INET;
    server.sin_port = htons(portNum);
    if (connect(conn, (struct sockaddr*) &server, sizeof(server))) {
        closesocket(conn);
        return 0;
    }
    
    return conn;
}


/*---------------------------------------------------------------------------------------
 * Function: HTTP_GetHeaderLength
 * Returns the size of the header in the passed server response string.
 *
 * Parameters:
 * content - The full response string from the server.
 *
 * Returns:
 * The length of the header section in the response string.
 *
 *---------------------------------------------------------------------------------------*/
int HTTP_GetHeaderLength(char *content) {
    const char *srchStr1 = "\r\n\r\n";
	const char *srchStr2 = "\n\r\n\r";
    char *FindPos = NULL;
    int OffSet = -1;

    FindPos = strstr(content, srchStr1);
    if (FindPos != NULL) {
        OffSet = FindPos - content;
        OffSet += strlen(srchStr1);
    } else {
        FindPos = strstr(content, srchStr2);
        if (FindPos != NULL)
        {
            OffSet = FindPos - content;
            OffSet += strlen(srchStr2);
        }
    }

    return OffSet;
}


/*
int main() {
    WSADATA wsaData;
    char *memBuffer = NULL;

    if (WSAStartup(0x101, &wsaData) != 0) { printf("startup failure"); }

    memBuffer = HTTP_GetContent("ipwho.is", "/20.54.36.229");

    printf("\n%s\n\n", memBuffer);

    if (memBuffer != NULL) free (memBuffer);
    WSACleanup();
}
*/
