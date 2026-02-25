Windows PE Packer with Mutation Engine
A Windows x64 PE packer that redirects execution flow through a custom stub section, featuring a mutation engine for instruction-level code transformation and a control flow flattener for obfuscation.

⚠️ Educational/Research purposes only. This project was built to understand PE internals, code mutation techniques, and Windows executable structure.


Features

Custom Stub Injection – Adds a new .stub PE section containing a custom entry point that resolves and jumps to the original entry point (OEP) at runtime
Junk Code Insertion – Randomly injects semantically neutral instruction sequences between real instructions to increase entropy and disrupt static analysis
Control Flow Flattening – Prepends a CFG chaos stub before the entry point logic
Mutation Engine – Performs instruction-level substitutions on the .text section:

MOV reg64, reg64 → LEA reg64, [reg64+0] (semantically identical)
MOV reg64, 0 → XOR reg64, reg64 (smaller encoding, same result)
XOR reg, reg → SUB reg, reg (same zeroing effect)
SUB reg, reg → AND reg, 0 (equivalent zero-out)




How It Works
1. PE Parsing
The target executable is parsed using LIEF, which provides read/write access to PE structures including sections, headers, and the optional header entry point field.
2. Stub Generation
A new .stub section is generated using LIEF. The stub:

Reads the PEB via gs:[0x60] to get the image base at runtime
Calculates the OEP by adding the stored RVA to the image base
Inserts randomized junk instructions around the real logic
Transfers execution to the original entry point via push rax / ret

3. Entry Point Redirection
The PE optional header's AddressOfEntryPoint is overwritten to point to the new .stub section, so the Windows executable loader executes the stub first.
4. Mutation Engine
Built on Zydis (x64 disassembler/encoder). The engine:

Decodes every instruction in the .text section
Identifies mutation candidates based on mnemonic and operand types
Re-encodes equivalent replacement instructions
Patches the bytes back into the section




Usage
packer.exe <target.exe>
Output is written to packed.exe in the current directory.


Current Limitations

Mutation is marked as unstable in the current build – packed executables may crash depending on instruction padding assumptions
Virtualization engine is a planned feature, not yet implemented
No support for 32-bit PE targets


What I Learned Building This

PE file format internals (sections, optional header, RVA vs raw offset)
How packers redirect execution using custom sections
x64 instruction encoding with Zydis encoder API


