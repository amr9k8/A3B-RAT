#pragma once
#pragma once
#pragma  comment(lib, "user32")
#pragma  comment(lib, "advapi32")
#include <windows.h>
#include <fstream>
#include <ctime>
#include <csignal>
#include <iostream>
#include < algorithm >
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#pragma once

bool SaveScreenshotToFile(const char* filename, std::vector<char> buffer, int width, int height)
{
    std::cout << "total image size  = " << std::to_string(buffer.size()) << std::endl;

    // Save the bitmap as a BMP file
    BITMAPFILEHEADER bmfHeader = { 0 };
    bmfHeader.bfType = 'MB';
    bmfHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + (width * height * 3);
    bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    BITMAPINFOHEADER bih = { sizeof(BITMAPINFOHEADER), width, height, 1, 24, BI_RGB, 0, 0, 0, 0, 0 };
    std::ofstream outfile(filename, std::ios::binary);
    if (!outfile)
    {
        // Failed to open file
        return false;
    }
    outfile.write((char*)&bmfHeader, sizeof(BITMAPFILEHEADER));
    outfile.write((char*)&bih, sizeof(BITMAPINFOHEADER));
    outfile.write(buffer.data(), width * height * 3);
    outfile.close();

    return true;
}