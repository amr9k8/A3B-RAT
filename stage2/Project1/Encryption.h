
#include <windows.h>
#include <fstream>
#include <ctime>
#include <csignal>
#include <bitset>
#include <sstream>
#pragma once
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