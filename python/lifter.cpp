//
// Created by florian on 08.01.17.
//

#include "lifter.h"

#include <iostream>
#include <string>
#include <sstream>
#include <system_error>

#include <llvm/Bitcode/ReaderWriter.h>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/ToolOutputFile.h>

#include "mcsema/Arch/Arch.h"

//#include "mcsema/BC/Lift.h"
#include "lift.h"
#include "mcsema/BC/Util.h"

using namespace std;
using namespace boost;
using namespace llvm;


Lifter::Lifter(std::string os, std::string arch, boost::python::object input)
{
	this->os = os;
	this->arch = arch;

	ignore_unsupported_insts = false;
	add_breakpoints = false;
	add_tracer = false;

	context = new llvm::LLVMContext;

	if (!InitArch(context, os, arch))
	{
		std::cerr << "Cannot initialize for arch " << arch << " and OS " << os << std::endl;
		return;
	}

	python::extract<NativeModulePtr> module_extract(input);
	if(module_extract.check())
		this->module = module_extract();
	else
	{
		std::cerr << "Reading module ..." << std::endl;
		std::string cfg_file = python::extract<std::string>(input);
		this->module = ReadProtoBuf(cfg_file);
	}
}

static VA FindSymbolInModule(NativeModulePtr mod, const std::string &sym_name) {
	for (auto &sym : mod->getEntryPoints()) {
		if (sym.getName() == sym_name) {
			return sym.getAddr();
		}
	}
	return static_cast<VA>( -1);
}

bool Lifter::Execute()
{
	if (python::len(entry_points) == 0)
	{
		std::cerr << "At least one entry point must be specified" << std::endl;
		return false;
	}


	auto M = CreateModule(context);
	if (!M)
	{
		return false;
	}

	auto triple = M->getTargetTriple();

	if(!module)
	{
		outs() << "No module.\n";
		return false;
	}

	//reproduce NativeModule from CFG input argument
	try
	{
		//now, convert it to an LLVM module
		ArchInitAttachDetach(M);

		if (!LiftCodeIntoModule(module, M, ignore_unsupported_insts, add_breakpoints, add_tracer))
		{
			std::cerr << "Failure to convert to LLVM module!" << std::endl;
			return false;
		}

		std::set<VA> entry_point_pcs;
		for(unsigned int i=0; i<python::len(entry_points); i++)
		{
			std::string entry_point_name = python::extract<std::string>(entry_points[i]);

			auto entry_pc = FindSymbolInModule(module, entry_point_name);
			if (entry_pc != static_cast<VA>( -1))
			{
				std::cerr << "Adding entry point: " << entry_point_name << std::endl
						  << entry_point_name << " is implemented by sub_" << std::hex
						  << entry_pc << std::endl;

				if ( !ArchAddEntryPointDriver(M, entry_point_name, entry_pc))
					return false;

				entry_point_pcs.insert(entry_pc);
			}
			else
			{
				std::cerr << "Could not find entry point: " << entry_point_name
						  << "; aborting" << std::endl;
				return false;
			}
		}

		RenameLiftedFunctions(module, M, entry_point_pcs);


		raw_string_ostream os(bitcode_data);
		WriteBitcodeToFile(M, os);

	}
	catch (std::exception &e)
	{
		std::cerr << "error: " << std::endl << e.what() << std::endl;
		return false;
	}

	return true;



	/*try
	{
		if(!module)
		{
			outs() << "No module.\n";
			return false;
		}

		// set native module target
		cout << "Setting initial triples..." << endl;
		module->setTarget(x86_target);
		module->setTargetTriple(target_triple);

		// TODO
		//bool IgnoreUnsupported = false;
		//if(IgnoreUnsupported)
		//{
		//	ignoreUnsupportedInsts = true;
		//}

		//now, convert it to an LLVM module
		cout << "Getting LLVM module..."  << endl;
		llvm::Module  *M = createModuleForArch(module->name(), target_triple);

		if(!M)
		{
			cout << "Unable to get LLVM module" << endl;
			return false;
		}

		//bool modResult = false;

		initRegStateStruct(M);
		ArchInitAttachDetach(M);
		initInstructionDispatch();

		cout << "Converting to LLVM..."  << endl;
		if (!liftNativeCodeIntoModule(module, M))
		{
			std::cerr << "Failure to convert to LLVM module!" << std::endl;
			return false;
		}


		std::set<VA> entry_point_pcs;

		for(unsigned int i=0; i<python::len(entry_points); i++)
		{
			std::string entry_point_name = python::extract<std::string>(entry_points[i]);

			std::cerr << "Adding entry point: " << entry_point_name << std::endl;

			auto entry_pc = findSymInModule(module, entry_point_name);
			if ((VA)(-1) != entry_pc)
			{
				std::cerr << entry_point_name << " is implemented by sub_" << std::hex
						  << entry_pc << std::endl;

				if (!ArchAddEntryPointDriver(M, entry_point_name, entry_pc)) {
					return false;
				}

				entry_point_pcs.insert(entry_pc);
			}
			else
			{
				llvm::errs() << "Could not find entry point: " << entry_point_name
							 << "; aborting\n";
				return false;
			}
		}

		renameLiftedFunctions(module, M, entry_point_pcs);

		bool ShouldVerify = true; // TODO
		// will abort if verification fails
		if (ShouldVerify && llvm::verifyModule( *M, &errs()))
		{
			std::cerr << "Could not verify module!\n";
			return false;
		}

		// TODO: maybe an option for this?
		//M->addModuleFlag(llvm::Module::Error, "Debug Info Version", (uint32_t)DEBUG_METADATA_VERSION);
		//M->addModuleFlag(llvm::Module::Error, "Dwarf Version", 3);

		raw_string_ostream os(bitcode_data);
		WriteBitcodeToFile(M, os);
	}
	catch (std::exception &e)
	{
		std::cerr << "error: " << std::endl << e.what() << std::endl;
		return false;
	}
	*/
}

bool Lifter::ExecuteAndSave(std::string output_file)
{
	if(!Execute())
		return false;

	try
	{
		std::error_code error_info;
		llvm::tool_output_file Out(output_file.c_str(), error_info, sys::fs::F_None);
		Out.os() << bitcode_data;
		Out.keep();
	}
	catch(std::exception &e)
	{
		cout << "error: " << endl << e.what() << endl;
		return false;
	}

	return true;
}