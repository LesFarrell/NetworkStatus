#ifndef HTTP_REQUEST_HEADER
#define HTTP_REQUEST_HEADER

#include <winsock2.h>

#define HTTP_BufferSize 512



// Prototypes.
char* HTTP_GetContent(char * host, char *path);
SOCKET HTTP_ConnectToServer(char* szServerName, WORD portNum);
int HTTP_GetHeaderLength(char *content);

#endif