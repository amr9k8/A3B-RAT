#pragma once
//-- The C standard Library
//#include <cstdlib>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib") //--Pragma comment for linker.
//#include <windows.h>
//#include <winsock2.h>



#define _DEBUG_
#define MAX_BUF (1024*64)
#define socketPort 3333
//#define ipv4ADDR "192.168.1.107"
#define ipv4ADDR "197.58.141.243"



 //Function to connect to server
bool connectToServer(SOCKET clientId) {
    // Create a socket address
    sockaddr_in socketAddress;
    socketAddress.sin_family = AF_INET;
    socketAddress.sin_port = htons(socketPort);
    inet_pton(AF_INET, ipv4ADDR, &socketAddress.sin_addr);

    // Connect to the server
    if (connect(clientId, (sockaddr*)&socketAddress, sizeof(socketAddress)) == SOCKET_ERROR) {
        //std::cerr << "Error connecting to server: " << WSAGetLastError() << std::endl;
        return false;
    }
    //std::cout << "Connected to server" << std::endl;
    return true;
}

// Function to create a client socket
SOCKET create_socket_clientid() {
    // Initialize Winsock
    WSADATA wsaData;
    int error = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (error != 0) {
       // std::cerr << "WSAStartup failed with error: " << error << std::endl;
        return INVALID_SOCKET;
    }

    // Create a client socket
    SOCKET clientId = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientId == INVALID_SOCKET) {
        //std::cerr << "Failed to create socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return INVALID_SOCKET;
    }
    return clientId;
}
