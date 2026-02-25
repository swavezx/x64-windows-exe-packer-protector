#include <iostream>
#include <windows.h>
#include "..\externals\Keystone/include\keystone\keystone.h"
#include "..\Ctf\ctf.h"
#include <vector>
#include <format>


std::vector<uint8_t> AssembleCode(const char* asm_code) {
    ks_engine* ks;
    ks_err err;

    // Initialize for x64
    err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
    if (err != KS_ERR_OK) {
       /std::cout << "[-] Keystone error: " << ks_strerror(err) << "\n";
        return {};
    }

    unsigned char* encode;
    size_t size;
    size_t count;

    // Assemble
    if (ks_asm(ks, asm_code, 0, &encode, &size, &count) != KS_ERR_OK) {
        std::cout << "[-] Assembly failed: " << ks_strerror(ks_errno(ks)) << "\n";
        ks_close(ks);
        return {};
    }

   

    // Copy to vector
    std::vector<uint8_t> code(encode, encode + size);

    // Free Keystone memory
    ks_free(encode);
    ks_close(ks);

    return code;
}



// Generate stub with OEP
std::vector<uint8_t> GenerateStub(DWORD oep_rva) {
    Sleep(100);
    srand(GetTickCount());


    std::string oep_str = "lea rax, [rax + 0x" + std::format("{:X}", oep_rva) + "]";

    
    std::vector<std::string> junk_op;
    std::vector<std::string> stubcode;
    std::vector<uint8_t> stub;
    std::string final_stub;
        



    stubcode.push_back("mov rax, gs:[0x60]");
    stubcode.push_back("mov rax, [rax+0x10]");
    stubcode.push_back(oep_str); 
    stubcode.push_back("push rax"); 
    stubcode.push_back("ret"); 
    


    // Register manipulation - no effect due to push/pop
    junk_op.push_back("push rbx\nxor rbx, rbx\npop rbx");
    junk_op.push_back("push rcx\nnot rcx\nnot rcx\npop rcx");
    junk_op.push_back("push rdx\nmov rdx, 0x1337\nxor rdx, 0x1337\npop rdx");
    junk_op.push_back("push rbx\nror rbx, 7\nrol rbx, 7\npop rbx");

    // Stack-based junk - reads real stack values
    junk_op.push_back("push rbx\nmov rbx, [rsp+16]\nimul rbx, 0x1337\npop rbx");
    junk_op.push_back("push rcx\nmov rcx, [rsp+8]\nxor rcx, [rsp+24]\npop rcx");
    junk_op.push_back("push rbx\nmov rbx, [rsp+16]\nror rbx, 3\nadd rbx, [rsp+8]\npop rbx");

    // Flags manipulation - no visible effect
    junk_op.push_back("push rbx\nmov rbx, [rsp+8]\ntest rbx, rbx\npop rbx");
    junk_op.push_back("push rbx\nmov rbx, [rsp+16]\ncmp rbx, 0xFF\npop rbx");

    // Arithmetic that cancels itself out
    junk_op.push_back("push rbx\nmov rbx, [rsp+8]\nadd rbx, 0x55\nsub rbx, 0x55\npop rbx");
    junk_op.push_back("push rbx\nmov rbx, [rsp+8]\nshl rbx, 4\nshr rbx, 4\npop rbx");


    


    
    stub.insert(stub.end(),
        cfg, cfg + cfg_chaos_size); //control flow flatterer
    

    for (int i = 0; i < stubcode.size(); i++) {
       
        final_stub += stubcode[i] + "\n";

		// Randomly insert junk instructions between real ones
        if (rand() % 2) {
            int junk_index = rand() % junk_op.size();
            final_stub += junk_op[junk_index] + "\n";
            
        }
    }

 

    


   auto oep_jump = AssembleCode(final_stub.c_str());
   
   stub.insert(stub.end(), oep_jump.begin(), oep_jump.end());
    printf("\n");
    return stub;
}