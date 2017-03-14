//
// Created by florian on 08.01.17.
//

#ifndef _MCSEMA_PYTHON_CFG_TO_LLVM_H
#define _MCSEMA_PYTHON_CFG_TO_LLVM_H

#include <string>
#include <vector>

#include <boost/python.hpp>
#include <llvm/Support/TargetRegistry.h>
#include <mcsema/CFG/CFG.h>

//#include "mcsema/cfgToLLVM/raiseX86.h"

class CFGToLLVM
{
	private:
		//std::string target_triple;
		//const llvm::Target *x86_target;

		NativeModulePtr module;

		std::string os;
		std::string arch;
		boost::python::list entry_points;

		std::string bitcode_data;

	public:
		CFGToLLVM(boost::python::object input);

		bool Execute();
		bool ExecuteAndSave(std::string output_file);

		const std::string GetOS() const						{ return os; }
		void SetOS(std::string os)							{ this->os = os; }

		const std::string GetArch() const					{ return arch; }
		void SetArch(std::string arch)						{ this->arch = arch;}

		//const std::string GetTargetTriple() const			{ return target_triple; }
		//void SetTargetTriple(std::string triple)			{ this->target_triple = triple; }

		NativeModulePtr GetNativeModule() const				{ return module; }
		void SetNativeModule(NativeModulePtr module)		{ this->module = module; }

		boost::python::list GetEntryPoints() const			{ return entry_points; }
		void SetEntryPoints(boost::python::list l)			{ this->entry_points = l; }



		std::string GetBitcode() const	 						{ return bitcode_data; }
};

#endif
