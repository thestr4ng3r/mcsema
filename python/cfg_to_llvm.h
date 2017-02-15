//
// Created by florian on 08.01.17.
//

#ifndef _MCSEMA_PYTHON_CFG_TO_LLVM_H
#define _MCSEMA_PYTHON_CFG_TO_LLVM_H

#include <string>
#include <vector>

#include <boost/python.hpp>
#include <llvm/Support/TargetRegistry.h>

#include "mcsema/cfgToLLVM/raiseX86.h"

class CFGToLLVM
{
	private:
		std::string target_triple;
		const llvm::Target *x86_target;

		NativeModulePtr module;

		boost::python::list entry_points;

		std::string bitcode_data;

		void LookupTarget();

	public:
		CFGToLLVM(std::string target_triple, boost::python::object input);

		bool Execute();
		bool ExecuteAndSave(std::string output_file);

		const std::string GetTargetTriple() const			{ return target_triple; }
		void SetTargetTriple(std::string triple)			{ this->target_triple = triple; }

		NativeModulePtr GetNativeModule() const				{ return module; }
		void SetNativeModule(NativeModulePtr module)		{ this->module = module; }

		boost::python::list GetEntryPoints() const			{ return entry_points; }
		void SetEntryPoints(boost::python::list l)			{ this->entry_points = l; }



		std::string GetBitcode() const	 						{ return bitcode_data; }
};

#endif
