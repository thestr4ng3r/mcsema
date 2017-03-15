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
#include <llvm/IR/LLVMContext.h>

//#include "mcsema/cfgToLLVM/raiseX86.h"

class Lifter
{
	private:
		//std::string target_triple;
		//const llvm::Target *x86_target;
		llvm::LLVMContext *context;

		NativeModulePtr module;

		std::string os;
		std::string arch;
		boost::python::list entry_points;

		std::string bitcode_data;


		bool ignore_unsupported_insts;
		bool add_breakpoints;
		bool add_tracer;


	public:
		Lifter(std::string os, std::string arch, boost::python::object input);

		bool Execute();
		bool ExecuteAndSave(std::string output_file);

		const std::string GetOS() const						{ return os; }
		//void SetOS(std::string os)						{ this->os = os; }

		const std::string GetArch() const					{ return arch; }
		//void SetArch(std::string arch)					{ this->arch = arch;}

		bool GetIgnoreUnsupportedInsts() const				{ return ignore_unsupported_insts; }
		void SetIgnoreUnsupportedInsts(bool v)				{ this->ignore_unsupported_insts = v; }

		bool GetAddBreakpoints() const						{ return add_breakpoints; }
		void SetAddBreakpoints(bool v)						{ this->add_breakpoints = v; }

		bool GetAddTracer() const							{ return add_tracer; }
		void SetAddTracer(bool v)							{ this->add_tracer = v; }

		boost::python::list GetEntryPoints() const			{ return entry_points; }
		void SetEntryPoints(boost::python::list l)			{ this->entry_points = l; }

		NativeModulePtr GetNativeModule() const				{ return module; }
		void SetNativeModule(NativeModulePtr module)		{ this->module = module; }


		std::string GetBitcode() const	 						{ return bitcode_data; }
};

#endif
