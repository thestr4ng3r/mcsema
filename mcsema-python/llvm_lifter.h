//
// Created by florian on 23.11.16.
//

#ifndef MC_SEMA_LLVM_LIFTER_H
#define MC_SEMA_LLVM_LIFTER_H

#include <string>
#include <vector>

#include "cfg_recover.h"

class LLVMLifter
{
	private:
		std::vector<std::string> entry_symbol; // TODO
		std::vector<std::string> entry_point; // TODO

		bool ignore_native_entry_points = true;
		bool debug_mode = false;

		NativeModulePtr MakeNativeModule(ExecutableContainer *exc, ExternalFunctionMap &funcs);

	public:
		LLVMLifter();

		int BinDescend(std::string in_filename, std::string out_filename);
};

#endif //MC_SEMA_LLVM_LIFTER_H
