#pragma once
#include <vector>

#include <windows.h>
std::vector<uint8_t> GenerateStub(DWORD oep_rva);
std::vector<uint8_t> AssembleCode(const char* asm_code);