
#include <llvm/Support/TargetSelect.h>
#include "mcsema_init.h"

void InitializeMCSema()
{
	llvm::InitializeAllTargetInfos();
	llvm::InitializeAllTargetMCs();
	llvm::InitializeAllAsmParsers();
	llvm::InitializeAllDisassemblers();
}