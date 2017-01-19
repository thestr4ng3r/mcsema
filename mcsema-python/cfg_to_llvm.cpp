//
// Created by florian on 08.01.17.
//

#include "cfg_to_llvm.h"

#include "llvm/Bitcode/BitstreamWriter.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/Debug.h"
#include <toLLVM.h>
#include <toModule.h>
#include <raiseX86.h>
#include <llvm/IR/Verifier.h>
#include <peToCFG.h>
#include <InstructionDispatch.h>

using namespace std;
using namespace boost;
using namespace llvm;



llvm::Module *createModuleForArch(std::string name, const std::string &triple)
{
	llvm::Module *M = new llvm::Module(name, llvm::getGlobalContext());
	llvm::Triple TT = llvm::Triple(triple);
	M->setTargetTriple(triple);

	std::string layout;

	if (TT.getOS() == llvm::Triple::Win32)
	{
		if (TT.getArch() == llvm::Triple::x86)
		{
			layout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-f80:128:128-v64:64:64-v128:128:128-a0:0:64-f80:32:32-n8:16:32-S32";
		}
		else if (TT.getArch() == llvm::Triple::x86_64)
		{
			layout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128";
		}
		else
		{
			std::cerr << "Unsupported arch in triple: " << triple << "\n";
			return nullptr;
		}
	}
	else if (TT.getOS() == llvm::Triple::Linux)
	{
		if (TT.getArch() == llvm::Triple::x86)
		{
			layout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-f32:32:32-f64:32:64-v64:64:64-v128:128:128-a0:0:64-f80:32:32-n8:16:32-S128";
		}
		else if (TT.getArch() == llvm::Triple::x86_64)
		{
			// x86_64-linux-gnu
			layout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128";
		}
		else
		{
			std::cerr << "Unsupported arch in triple: " << triple << "\n";
			return nullptr;
		}
	}
	else
	{
		std::cerr << "Unsupported OS in triple: " << triple << "\n";
		return nullptr;
	}

	M->setDataLayout(layout);
	return M;
}




static VA findSymInModule(NativeModulePtr mod, const std::string &sym_name)
{
	for (auto &sym : mod->getEntryPoints())
	{
		if (sym.getName() == sym_name)
		{
			return sym.getAddr();
		}
	}
	return (VA)(-1);
}

CFGToLLVM::CFGToLLVM(std::string target_triple, boost::python::object input)
{
	this->target_triple = target_triple;
	LookupTarget();

	python::extract<NativeModulePtr> module_extract(input);
	if(module_extract.check())
		this->module = module_extract();
	else
	{
		std::cerr << "Reading module ..." << std::endl;
		std::string cfg_file = python::extract<std::string>(input);
		this->module = readModule(cfg_file, ProtoBuff, list<VA>(), x86_target);
	}
}

void CFGToLLVM::LookupTarget()
{
	std::string errstr;
	cout << "Looking up target..." << endl;
	x86_target = TargetRegistry::lookupTarget(target_triple, errstr);

	if(x86_target == nullptr)
	{
		std::cerr << "Could not find target triple: " << target_triple << "\n";
		std::cerr << "Error: " << errstr << "\n";
		//return 0;
	}
}


bool CFGToLLVM::Execute()
{
	try
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
		/*bool IgnoreUnsupported = false;
		if(IgnoreUnsupported)
		{
			ignoreUnsupportedInsts = true;
		}*/

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

	return true;
}

bool CFGToLLVM::ExecuteAndSave(std::string output_file)
{
	if(!Execute())
		return false;

	try
	{
		string error_info;
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
