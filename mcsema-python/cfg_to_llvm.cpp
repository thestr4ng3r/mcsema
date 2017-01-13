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

using namespace std;
using namespace boost;
using namespace llvm;



llvm::Module  *getLLVMModule(string name, const std::string &triple)
{
	llvm::Module  *M = new llvm::Module(name, llvm::getGlobalContext());
	llvm::Triple TT = llvm::Triple(triple);
	M->setTargetTriple(triple);


	std::string layout;

	if(TT.getOS() == llvm::Triple::Win32)
	{
		if(TT.getArch() == llvm::Triple::x86)
			layout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-f80:128:128-v64:64:64-v128:128:128-a0:0:64-f80:32:32-n8:16:32-S32";
		else if(TT.getArch() == llvm::Triple::x86_64)
			layout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128";
		else
		{
			std::cerr << "Unsupported arch in triple: " << triple << "\n";
			return nullptr;
		}
	}
	else if (TT.getOS() == llvm::Triple::Linux)
	{
		if(TT.getArch() == llvm::Triple::x86)
			layout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-f32:32:32-f64:32:64-v64:64:64-v128:128:128-a0:0:64-f80:32:32-n8:16:32-S128";
		else if(TT.getArch() == llvm::Triple::x86_64)
			layout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"; // x86_64-linux-gnu
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

	doGlobalInit(M);

	return M;
}




static VA string_to_int(const std::string &s)
{
	VA ret;
	if(s.size() > 1 && (s[1] == 'x' || s[1] == 'X'))
		ret = strtol(s.c_str(), NULL, 16);
	else
		ret = strtol(s.c_str(), NULL, 10);

	// sanity check
	if( ret == 0 && s[0] != '0')
		throw LErr(__LINE__, __FILE__, "Could not convert string to int: "+s);

	return ret;
}


static bool findSymInModule(NativeModulePtr mod, const std::string &sym, VA &ep)
{
	const vector<NativeModule::EntrySymbol> &syms = mod->getEntryPoints();
	for(vector<NativeModule::EntrySymbol>::const_iterator itr = syms.begin(); itr != syms.end(); itr++)
	{
		if(itr->getName() == sym)
		{
			ep = itr->getAddr();
			return true;
		}
	}

	ep = 0;
	return false;
}

// check if an entry point (to_find) is in the list of possible
// entry points for this module
static bool findEPInModule(NativeModulePtr mod, VA to_find, VA &ep)
{
	const vector<NativeModule::EntrySymbol> &syms = mod->getEntryPoints();
	for(vector<NativeModule::EntrySymbol>::const_iterator itr = syms.begin(); itr != syms.end(); itr++)
	{
		if(itr->getAddr() == to_find)
		{
			ep = to_find;
			return true;
		}
	}

	ep = 0;
	return false;
}

static bool haveDriverFor(const std::vector<DriverEntry> &drvs, const std::string &epname)
{
	for(std::vector<DriverEntry>::const_iterator it = drvs.begin();
		it != drvs.end();
		it++)
	{
		// already have a driver for this entry point
		if (epname == it->sym) {
			cout << "Already have driver for: " << epname << std::endl;
			return true;
		}
	}

	return false;
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
	vector<DriverEntry> drivers;

	for(unsigned int i=0; i<python::len(driver_entries); i++)
		drivers.push_back(python::extract<DriverEntry>(driver_entries[i]));


	if(!module)
	{
		outs() << "No module.\n";
		return false;
	}


	// set native module target
	cout << "Setting initial triples..." << endl;
	module->setTarget(x86_target);
	module->setTargetTriple(target_triple);

	const std::vector<NativeModule::EntrySymbol>& native_eps = module->getEntryPoints();
	std::vector<NativeModule::EntrySymbol>::const_iterator natep_it;
	cout << "Looking at entry points..."  << endl;
	for(natep_it = native_eps.begin(); natep_it != native_eps.end(); natep_it++)
	{
		const std::string &epname = natep_it->getName();
		if(!haveDriverFor(drivers, epname) && natep_it->hasExtra() )
		{
			DriverEntry d;
			d.name = "driver_"+epname;
			d.sym = epname;
			d.ep = 0;
			d.argc = natep_it->getArgc();
			d.is_raw = false;
			d.returns = natep_it->doesReturn();
			d.cconv = natep_it->getConv();
			drivers.push_back(d);
			cout << "Automatically generating driver for: " << epname << std::endl;
		}
	}


	if(drivers.size() == 0)
	{
		cout << "At least one driver must be specified. Please use the -driver option\n";
		return false;
	}

	/*bool OutputModule = false;
	if(OutputModule)
		doPrintModule(mod);*/


	/*bool IgnoreUnsupported = false;
	if(IgnoreUnsupported)
	{
		ignoreUnsupportedInsts = true;
	}*/

	//now, convert it to an LLVM module
	cout << "Getting LLVM module..."  << endl;
	llvm::Module  *M = getLLVMModule(module->name(), target_triple);

	if(!M)
	{
		cout << "Unable to get LLVM module" << endl;
		return false;
	}

	bool modResult = false;

	try
	{
		cout << "Converting to LLVM..."  << endl;
		modResult = natModToModule(module, M, outs());
	}
	catch(std::exception &e)
	{
		cout << "error: " << endl << e.what() << endl;
		return false;
	}

	if(!modResult)
	{
		cout << "Failure to convert to LLVM module!" << endl;
		return false;
	}


	try
	{
		for(vector<DriverEntry>::const_iterator itr = drivers.begin(); itr != drivers.end(); itr++)
		{
			VA ep = 0;

			// if this is a symbolic reference, look it up
			if(itr->ep == 0 && itr->sym != "")
			{
				if(!findSymInModule(module, itr->sym, ep))
				{
					llvm::errs() << "Could not find entry point: " << itr->sym << "; aborting\n";
					return false;
				}
			}
			else
			{
				// if this is an address reference, make sure its
				// a valid entry point
				if(!findEPInModule(module, itr->ep, ep))
				{
					llvm::errs() << "Could not find entry address: " <<
								 to_string<VA>(itr->ep, hex) << "; aborting\n";
					return false;
				}
			}

			cout << "Adding entry point: " << itr->name << std::endl;

			if(itr->is_raw == true)
			{
				if(module->is64Bit())
					x86_64::addEntryPointDriverRaw(M, itr->name, ep);
				else
					x86::addEntryPointDriverRaw(M, itr->name, ep);
			}
			else
			{
				if(module->is64Bit())
					x86_64::addEntryPointDriver(M, itr->name, ep, itr->argc, itr->returns, outs(), itr->cconv, itr->sign);
				else
					x86::addEntryPointDriver(M, itr->name, ep, itr->argc, itr->returns, outs(), itr->cconv);
			}

		} // for vector<DriverEntry>




		bool EnablePostAnalysis = true; // TODO

		if(EnablePostAnalysis)
		{
			cout << "Doing post analysis passes...\n";
			doPostAnalysis(module, M);
		}
		else
		{
			cout << "NOT doing post analysis passes.\n";
		}


		bool ShouldVerify = true; // TODO

		// will abort if verification fails
		if(ShouldVerify && llvm::verifyModule(*M, &errs()))
		{
			cerr << "Could not verify module!\n";
			return false;
		}

		M->addModuleFlag(llvm::Module::Error, "Debug Info Version", (uint32_t)DEBUG_METADATA_VERSION);
		M->addModuleFlag(llvm::Module::Error, "Dwarf Version", 3);

		raw_string_ostream os(bitcode_data);
		WriteBitcodeToFile(M, os);
	}
	catch(std::exception &e)
	{
		cout << "error: " << endl << e.what() << endl;
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
