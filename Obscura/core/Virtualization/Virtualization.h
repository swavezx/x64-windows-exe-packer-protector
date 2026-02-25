#pragma once
#include <windows.h>
#include <iostream>

#include <vector>
#include <cstdint>
#include <Zydis/Zydis.h>
#include "externals/LIEF/include/LIEF/LIEF.hpp"


enum VOpcode : uint8_t {
	VMOV = 0x01,
	VRET = 0xFF
};



struct InstructionInfos
{
	uint64_t rva;
	std::vector<uint8_t> bytes;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	bool was_mutated = false;
};



enum VReg : uint8_t {
	V0 = 0,  // rax
	V1 = 1,  // rbx
	V2 = 2,  // rcx
	V3 = 3,  // rdx
	V4 = 4,  // rsi
	V5 = 5,  // rdi
	V6 = 6,  // r8
	V7 = 7,  // r9
	V8 = 8,  // r10
	V9 = 9,  // r11
	V10 = 10, // r12
	V11 = 11, // r13
	V12 = 12, // r14
	V13 = 13, // r15

};

class VMengine
{


private:

	

	std::vector<InstructionInfos> inst;
	std::vector<uint8_t> bytecode;


	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	ZydisDecodedInstruction instruction;
	ZydisEncoderRequest req;
	ZydisDecoder decoder;
	ZydisFormatter formatter;
	uint64_t base_rva = 0;



public:

	VMengine()
    {
       
		

    }

};

struct VMContext
{
	uint64_t vregs[14];  
	uint8_t* bytecode;   
	uint64_t bytecode_size;
};
