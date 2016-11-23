//
// Created by florian on 23.11.16.
//

#include "llvm_lifter.h"

using namespace std;

LLVMLifter::LLVMLifter(std::string s)
{
	this->s = s;
}

string LLVMLifter::Test(std::string a, std::string b)
{
	return a + b + s;
}