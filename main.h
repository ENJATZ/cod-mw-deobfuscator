#pragma once
#include <Zydis/Zydis.h>
#pragma comment(lib,"Zydis.lib")

bool NewRegisterDecryption(ZydisRegister EncryptedPointer = ZYDIS_REGISTER_RBX, ZydisMnemonic EndMnemonic = ZYDIS_MNEMONIC_MOVZX, bool PrintAll = false, bool PrintReturn = true);
void ClearRegisterDecryption();
std::string ValidPointerCheck(const char* name, QWORD offset);

static int CurrentInstructionLength = 0;