//
// Created by florian on 08.01.17.
//

#ifndef _MCSEMA_PYTHON_CFG_TO_LLVM_H
#define _MCSEMA_PYTHON_CFG_TO_LLVM_H

#include <string>
#include <vector>

#include <boost/python.hpp>

#include "cfg_recover.h"

class CFGToLLVM
{
	private:
		std::string target_triple;
		const llvm::Target *x86_target;

		NativeModulePtr module;

		boost::python::list driver_entries;

		std::string bitcode_data;

		void LookupTarget();

	public:
		CFGToLLVM(std::string target_triple, boost::python::object input);
		//CFGToLLVM(std::string target_triple, std::string cfg_file);

		int Execute();

		const std::string GetTargetTriple() const			{ return target_triple; }
		void SetTargetTriple(std::string triple)			{ this->target_triple = triple; }

		NativeModulePtr GetNativeModule() const				{ return module; }
		void SetNativeModule(NativeModulePtr module)		{ this->module = module; }

		boost::python::list GetDrivers() const				{ return driver_entries; }
		void SetDrivers(boost::python::list drivers)		{ this->driver_entries = drivers; }



		std::string GetBitcode() const	 						{ return bitcode_data; }
};


struct DriverEntry
{
	bool is_raw;
	bool returns;
	int  argc;
	std::string name;
	std::string sym;
	std::string sign;
	VA ep;
	ExternalCodeRef::CallingConvention cconv;
};

#endif
