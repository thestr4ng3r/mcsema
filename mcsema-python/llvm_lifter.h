//
// Created by florian on 23.11.16.
//

#ifndef MC_SEMA_LLVM_LIFTER_H
#define MC_SEMA_LLVM_LIFTER_H

#include <string>

class LLVMLifter
{
	private:
		std::string s;

	public:
		LLVMLifter(std::string s);

		std::string Test(std::string a, std::string b);
};

#endif //MC_SEMA_LLVM_LIFTER_H
