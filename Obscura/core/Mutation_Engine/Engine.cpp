#include "Engine.h"
#include <iostream>
#include "externals/LIEF/include/LIEF/LIEF.hpp"
#include "..\Utils\Color.h"



void MutationEngine::parseText(LIEF::PE::Binary* binary)
{
    

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder,
        ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64);

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

  

    

    LIEF::PE::Section* TextSection = nullptr;
    for (auto& section : binary->sections())
    {
        if (section.name() == ".text")
        {
            TextSection = &section;
            break;
        }
    }

    if (!TextSection)
    {
        std::cout << "Text section not found\n";
        return;
    }

    auto span = TextSection->content();

    std::vector<uint8_t> code(span.begin(), span.end());
    base_rva = TextSection->virtual_address();

    size_t offset = 0;

    while (offset < code.size())
    {
        ZyanStatus status = ZydisDecoderDecodeFull(
            &decoder,
            code.data() + offset,
            code.size() - offset,
            &instruction,
            operands
        );

        if (!ZYAN_SUCCESS(status))
        {
            offset++;
            continue;
        }

        InstructionInfo info;
        info.rva = base_rva + offset;

        info.bytes = std::vector<uint8_t>(
            code.data() + offset,
            code.data() + offset + instruction.length
        );

        info.instruction = instruction;
        std::memcpy(info.operands, operands, sizeof(operands));

        inst.push_back(info);

        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
            instruction.operand_count, buffer, sizeof(buffer), info.rva, nullptr);

        
        


        offset += instruction.length;
    }

    

}


void MutationEngine::MutateCode(LIEF::PE::Binary* binary)
{
    parseText(binary);
    if (!inst.size())
    {
        std::cout << "No instructions found to mutate\n";
        return;
    }

 
    std::cout << "\n[+] Mutating " << std::dec << inst.size() << " instructions...\n";


    for (auto& info : inst)
    {
      
        switch (info.instruction.mnemonic)
        {
        case ZYDIS_MNEMONIC_MOV: //check if the instruction is a MOV instruction
        {
           
            memset(&req, 0, sizeof(req));

            if (info.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                info.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) //check if both operands are registers
            {
                if (ZydisRegisterGetClass(info.operands[0].reg.value) == ZYDIS_REGCLASS_GPR64 &&
                    ZydisRegisterGetClass(info.operands[1].reg.value) == ZYDIS_REGCLASS_GPR64) //check if both registers are 64-bit general-purpose registers
                {
                  
                    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
                    req.mnemonic = ZYDIS_MNEMONIC_LEA;
                    req.operand_count = 2;
                    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
                    req.operands[0].reg.value = info.operands[0].reg.value;
                    req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
                    req.operands[1].mem.base = info.operands[1].reg.value;
                    req.operands[1].mem.displacement = 0;
                    req.operands[1].mem.size = 8;  // 64-bit

                    uint8_t encoded[ZYDIS_MAX_INSTRUCTION_LENGTH];
                    ZyanUSize encoded_len = sizeof(encoded);
                    ZydisEncoderEncodeInstruction(&req, encoded, &encoded_len);

                    char original[256];
                    ZydisFormatterFormatInstruction(&formatter, &info.instruction, info.operands,
                        info.instruction.operand_count, original, sizeof(original), info.rva, nullptr);
                   


                    info.bytes.assign(encoded, encoded + encoded_len);
                    info.was_mutated = true;

                    ZydisDecodedInstruction test_inst;
                    ZydisDecodedOperand test_ops[ZYDIS_MAX_OPERAND_COUNT];
                    ZydisDecoderDecodeFull(&decoder, encoded, encoded_len, &test_inst, test_ops);

                    char buffer[256];
                    ZydisFormatterFormatInstruction(&formatter, &test_inst, test_ops,
                        test_inst.operand_count, buffer, sizeof(buffer), info.rva, nullptr);
                    

                }






            }



            // Check for MOV reg, imm with imm = 0, which can be replaced with XOR reg, reg

            if (info.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                info.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                if (ZydisRegisterGetClass(info.operands[0].reg.value) == ZYDIS_REGCLASS_GPR64 &&
                    info.operands[1].imm.value.u == 0)
                {
                   
                    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
                    req.mnemonic = ZYDIS_MNEMONIC_XOR;
                    req.operand_count = 2;
                    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
                    req.operands[0].reg.value = info.operands[0].reg.value;
                    req.operands[1].type = ZYDIS_OPERAND_TYPE_REGISTER;
                    req.operands[1].reg.value = info.operands[0].reg.value;


                    uint8_t encoded[ZYDIS_MAX_INSTRUCTION_LENGTH];
                    ZyanUSize encoded_len = sizeof(encoded);
                    ZydisEncoderEncodeInstruction(&req, encoded, &encoded_len);
                    char original[256];
                    ZydisFormatterFormatInstruction(&formatter, &info.instruction, info.operands,
                        info.instruction.operand_count, original, sizeof(original), info.rva, nullptr);

                    info.bytes.assign(encoded, encoded + encoded_len);
                    info.was_mutated = true;

                    ZydisDecodedInstruction test_inst;
                    ZydisDecodedOperand test_ops[ZYDIS_MAX_OPERAND_COUNT];
                    ZydisDecoderDecodeFull(&decoder, encoded, encoded_len, &test_inst, test_ops);

                    char buffer[256];
                    ZydisFormatterFormatInstruction(&formatter, &test_inst, test_ops,
                        test_inst.operand_count, buffer, sizeof(buffer), info.rva, nullptr);
                   


                }
            }


            break;
        }


        case ZYDIS_MNEMONIC_LEA:
        {
            



            break;

        }


        case ZYDIS_MNEMONIC_ADD:
        {
            
            break;
        }

        case ZYDIS_MNEMONIC_SUB:
        {
            

            memset(&req, 0, sizeof(req));

            auto regClass0 = ZydisRegisterGetClass(info.operands[0].reg.value);
            auto regClass1 = ZydisRegisterGetClass(info.operands[1].reg.value);

            if (info.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                info.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) //check if both operands are registers
            {
                if ((regClass0 == ZYDIS_REGCLASS_GPR64 || regClass0 == ZYDIS_REGCLASS_GPR32) &&
                    (regClass1 == ZYDIS_REGCLASS_GPR64 || regClass1 == ZYDIS_REGCLASS_GPR32)) //check if both registers are 64-bit general-purpose registers
                {
                  
                    if (info.operands[0].reg.value == info.operands[1].reg.value)
                    {
                    
                        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
                        req.mnemonic = ZYDIS_MNEMONIC_AND;
                        req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE; // Change the second operand to an immediate value so wee can change it to  0
                        req.operand_count = 2;
                        req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
                        req.operands[0].reg.value = info.operands[0].reg.value;
                        req.operands[1].imm.u = 0; //change the immediate value to 0



                        uint8_t encoded[ZYDIS_MAX_INSTRUCTION_LENGTH];
                        ZyanUSize encoded_len = sizeof(encoded);
                        ZydisEncoderEncodeInstruction(&req, encoded, &encoded_len);

                        char original[256];
                        ZydisFormatterFormatInstruction(&formatter, &info.instruction, info.operands,
                            info.instruction.operand_count, original, sizeof(original), info.rva, nullptr);
                        


                        info.bytes.assign(encoded, encoded + encoded_len);
                        info.was_mutated = true;

                        ZydisDecodedInstruction test_inst;
                        ZydisDecodedOperand test_ops[ZYDIS_MAX_OPERAND_COUNT];
                        ZydisDecoderDecodeFull(&decoder, encoded, encoded_len, &test_inst, test_ops);

                        char buffer[256];
                        ZydisFormatterFormatInstruction(&formatter, &test_inst, test_ops,
                            test_inst.operand_count, buffer, sizeof(buffer), info.rva, nullptr);
                     
                    }
                    else
                    {
                        std::cout << Color::yellow << "Found SUB instruction with different register operands at RVA: 0x" << std::hex << info.rva << "\n" << Color::reset;
                        std::cout << "--------------------\n";
                        std::cout << ZydisRegisterGetString(info.operands[0].reg.value) << "\n";
                        std::cout << ZydisRegisterGetString(info.operands[1].reg.value) << "\n";
                        std::cout << "--------------------\n";
                    }




                }


            }


            break;

        }

        case ZYDIS_MNEMONIC_XOR:
        {
            memset(&req, 0, sizeof(req));

            auto regClass0 = ZydisRegisterGetClass(info.operands[0].reg.value);
            auto regClass1 = ZydisRegisterGetClass(info.operands[1].reg.value);

            if (info.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                info.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) //check if both operands are registers
            {
                if ((regClass0 == ZYDIS_REGCLASS_GPR64 || regClass0 == ZYDIS_REGCLASS_GPR32) &&
                    (regClass1 == ZYDIS_REGCLASS_GPR64 || regClass1 == ZYDIS_REGCLASS_GPR32)) //check if both registers are 64-bit general-purpose registers
                {
                    if (info.operands[0].reg.value == info.operands[1].reg.value)
                    {
                    
                        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
                        req.mnemonic = ZYDIS_MNEMONIC_SUB;
                        req.operand_count = 2;
                        req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
                        req.operands[0].reg.value = info.operands[0].reg.value;
                        req.operands[1].reg.value = info.operands[0].reg.value;
                        req.operands[1].type = ZYDIS_OPERAND_TYPE_REGISTER;


                        uint8_t encoded[ZYDIS_MAX_INSTRUCTION_LENGTH];
                        ZyanUSize encoded_len = sizeof(encoded);
                        ZydisEncoderEncodeInstruction(&req, encoded, &encoded_len);

                        char original[256];
                        ZydisFormatterFormatInstruction(&formatter, &info.instruction, info.operands,
                            info.instruction.operand_count, original, sizeof(original), info.rva, nullptr);
                        //std::cout << "Original: " << original << "\n";


                        info.bytes.assign(encoded, encoded + encoded_len);
                        info.was_mutated = true;

                        ZydisDecodedInstruction test_inst;
                        ZydisDecodedOperand test_ops[ZYDIS_MAX_OPERAND_COUNT];
                        ZydisDecoderDecodeFull(&decoder, encoded, encoded_len, &test_inst, test_ops);

                        char buffer[256];
                        ZydisFormatterFormatInstruction(&formatter, &test_inst, test_ops,
                            test_inst.operand_count, buffer, sizeof(buffer), info.rva, nullptr);
                        
                    }




                }


            }
            break;
        }


        case ZYDIS_MNEMONIC_AND:
        {
            
            break;
        }


        }




    }








    LIEF::PE::Section* TextSection = nullptr;
    for (auto& section : binary->sections())
    {
        if (section.name() == ".text")
        {
            TextSection = &section;
            break;
        }
    }

    if (!TextSection)
    {
        std::cout << "Text section not found\n";
        return;
    }
    auto content = TextSection->content();
    std::vector<uint8_t> data(content.begin(), content.end());

    for (auto& info : inst)
    {
        if (!info.was_mutated) continue;

        size_t offset = info.rva - base_rva;
        for (size_t i = 0; i < info.bytes.size(); i++)
            data[offset + i] = info.bytes[i];

    }
    TextSection->content(data);


}

