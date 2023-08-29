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
bool SaveScreenshotToMemory(std::vector<char>& buffer, int& width, int& height)
{
    // Get the screen dimensions
    width = GetSystemMetrics(SM_CXSCREEN);
    height = GetSystemMetrics(SM_CYSCREEN);

    // Create a device context for the entire screen
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);

    // Create a bitmap to hold the screenshot
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);

    // Copy the screen to the bitmap
    BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);

    // Get the bitmap data
    BITMAPINFOHEADER bih = { sizeof(BITMAPINFOHEADER), width, height, 1, 24, BI_RGB, 0, 0, 0, 0, 0 };
    BITMAPINFO bInfo = { bih, { 0 } };
    int dataSize = width * height * 3;
    buffer.resize(dataSize);
    if (!GetDIBits(hdcScreen, hBitmap, 0, height, buffer.data(), &bInfo, DIB_RGB_COLORS))
    {
        // Failed to get bitmap data
        buffer.clear();
        width = 0;
        height = 0;
        SelectObject(hdcMem, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return false;
    }

    // Clean up
    SelectObject(hdcMem, hOldBitmap);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);

    return true;
}

bool SaveScreenshotToFile(std::string filename, std::vector<char> buffer, int width, int height)
{
    //// inputs to save image is buffer contain pixels,width,height
    //if (!SaveScreenshotToMemory(buffer, width, height))
    //{
    //    // Failed to save screenshot to memory
    //    return false;
    //}

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