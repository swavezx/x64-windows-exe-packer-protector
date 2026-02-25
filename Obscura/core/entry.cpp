#include <iostream>
#include <windows.h>
#include "externals/LIEF/include/LIEF/LIEF.hpp"
#include "stub/stub.h"
#include "Mutation_Engine/Engine.h"
#include "Virtualization/Virtualization.h"
#include "Utils/Color.h"
#include "Utils/Animation.h"








int main(int args, char* argv[])
{
    MutationEngine engine;
    VMengine Vengine;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    using namespace std::chrono_literals;
    namespace bk = barkeep;


	if (args != 2)
	{
		std::cout << "\n";
		std::cout << "\n";  
		std::cout << "[+] use your target application as parameter \n";
		std::cout << "\n";
		std::cout << "\n";
		std::cout << "\n";
	
		system("pause");
		return 0;
	}
	 auto binary = LIEF::PE::Parser::parse(argv[1]);
	 auto rvaOEP = binary->optional_header().addressof_entrypoint();
	 auto OEP = rvaOEP;

     

     

	SetConsoleOutputCP(CP_UTF8);
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);


	//Change colour to pink
	SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);


	std::cout << "\n";
	std::cout << "\n";
	std::cout << "				\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x84 \xE2\x96\x84\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x84 \xE2\x96\x84\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x88 \xE2\x96\x84\xE2\x96\x88\xE2\x96\x80 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x84  \n";
	std::cout << "				\xE2\x96\x88\xE2\x96\x88\xE2\x96\x84\xE2\x96\x84\xE2\x96\x88\xE2\x96\x80 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x84\xE2\x96\x84\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x88     \xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88   \xE2\x96\x88\xE2\x96\x88\xE2\x96\x84\xE2\x96\x84   \xE2\x96\x88\xE2\x96\x88\xE2\x96\x84\xE2\x96\x84\xE2\x96\x88\xE2\x96\x88\xE2\x96\x84 \n";
	std::cout << "				\xE2\x96\x88\xE2\x96\x88     \xE2\x96\x88\xE2\x96\x88  \xE2\x96\x88\xE2\x96\x88 \xE2\x96\x80\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x88 \xE2\x96\x80\xE2\x96\x88\xE2\x96\x84 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84 \xE2\x96\x88\xE2\x96\x88   \xE2\x96\x88\xE2\x96\x88\n";
	std::cout << "\n";
	std::cout << "\n";
	std::cout << "\n";
	std::cout << "\n";

	//back to white
	SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    //prints PACKER

	
    std::cout << "[+] adress of OEP[rva] -> 0x" << std::hex << rvaOEP << std::endl; //prints rva(relativ virtual adress) relativ from imagebase !


    auto oep_rva = binary->optional_header().addressof_entrypoint();
    std::cout << "[+] Original Entry Point (RVA): 0x" << std::hex << oep_rva << "\n";

    
    std::cout << "[+] Generating stub...";
    auto stubCode = GenerateStub(oep_rva);

    if (stubCode.empty()) {
        std::cout << "[-] Failed to generate stub!\n";
        system("pause");
        return 1;
    }

   

   

    std::cout << "[+] Adding stub section...\n";
    LIEF::PE::Section stubSection(".stub");
    stubSection.content(stubCode);
    stubSection.add_characteristic(

        LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE |
        LIEF::PE::Section::CHARACTERISTICS::MEM_READ
      
    );
    
    auto addedSection = binary->add_section(stubSection);
    if (!addedSection)
    {
        std::cout << "addedSection failed";
        system("pause");
    }
    std::cout << "[+] Stub section at RVA: 0x" << std::hex << addedSection->virtual_address() << "\n";

    // Redirect entry point
    
    binary->optional_header().addressof_entrypoint(addedSection->virtual_address());
    
    // Add imports if needed
    bool hasKernel32 = false;
    for (auto& imp : binary->imports()) {
        std::string name = imp.name();
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        if (name.find("kernel32") != std::string::npos) {
            hasKernel32 = true;
            break;
        }
    }

    

    if (!hasKernel32) {
        std::cout << "[+] Adding kernel32.dll import...\n";
        auto& kernel32 = binary->add_import("kernel32.dll");
        kernel32.add_entry("GetModuleHandleA");
    };



	



    auto anim = bk::Animation({ .message = "[+] Virtualizing code" });

   

    std::this_thread::sleep_for(5s);
    anim->done();
    


	std::cout << Color::magenta << "[*] Should your Application be mutated? (y/n): " << Color::reset;
	std::cout << Color::yellow << "[*] Not available rigth now\n" << Color::reset;
	char choice = 'n';
    std::cin >> choice;

    if(choice == 'y' || choice == 'Y')
    {
        
        auto anim = bk::Animation({ .message = "[+] Mutating code" });
       
        engine.MutateCode(binary.get());

        std::this_thread::sleep_for(5s);
        anim->done();

        

		

        std::cout << "[+] Writing packed.exe...\n";


        std::cout << "[+] Done!\n";
		std::cout << Color::yellow << "[+] Note: Mutation is a work in progress, expect some crashes and instability in the packed executable.\n" << Color::reset;
        std::cout << "[+] ";

        system("pause");
    }
    else
    {
        std::cout << "[+] Writing packed.exe without Mutation...\n";

        LIEF::PE::Builder::config_t config;
        config.imports = true;
        binary->write("packed.exe", config);

        std::cout << "[+] Done!\n";

        system("pause");
    }



    
    

   
}



