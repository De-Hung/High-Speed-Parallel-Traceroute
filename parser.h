#pragma once
#include "pch.h"

// Parses DNS response
void prsR(const char* rsp, int len, USHORT txid);
const char* rdName(const unsigned char* b, int len, int off, std::string& out, int& nxt);
bool parsePTR(const char* rsp, int len, std::string& out);