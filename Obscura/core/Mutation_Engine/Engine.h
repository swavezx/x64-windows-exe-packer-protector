#pragma once
#ifndef MUTATIONENGINE_H
#define MUTATIONENGINE_H

#include <vector>
#include <cstdint>
#include <Zydis/Zydis.h>
#include "externals/LIEF/include/LIEF/LIEF.hpp"

struct InstructionInfo
{
    uint64_t rva;
    std::vector<uint8_t> bytes;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    bool was_mutated = false;
};



struct MutationRule
{
    ZydisMnemonic target;
    ZydisOperandType op0_type;
    ZydisOperandType op1_type;
    ZydisRegisterClass reg_class;
    ZydisMnemonic replacement;
};




class MutationEngine
{
   

private:

   
    std::vector<InstructionInfo> inst;


    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZydisDecodedInstruction instruction;
    ZydisEncoderRequest req;
    ZydisDecoder decoder;
    ZydisFormatter formatter;
    uint64_t base_rva = 0;


public:

    MutationEngine()
    {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
      
        
    }
    
    void parseText(LIEF::PE::Binary* binary);
    void MutateCode(LIEF::PE::Binary* binary);
};

#endif
