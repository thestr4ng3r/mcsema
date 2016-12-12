//
// Created by florian on 23.11.16.
//


#include "llvm/ADT/Triple.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/Bitcode/BitstreamWriter.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/DataTypes.h"
#include "llvm/Support/Debug.h"
#include "bin_descend/cfg_recover.h"
#include <bincomm.h>
#include <peToCFG.h>
#include <toLLVM.h>
#include <toModule.h>
#include <raiseX86.h>
#include <LExcn.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <boost/filesystem.hpp>
#include "../mc-sema/common/to_string.h"
#include "../mc-sema/common/Defaults.h"

#include <boost/tokenizer.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>
#include <llvm/IR/Verifier.h>

#include "llvm_lifter.h"

using namespace std;
using namespace boost;
using namespace llvm;


void InitializeLLVMLifter()
{
	llvm::InitializeAllTargetInfos();
	llvm::InitializeAllTargetMCs();
	llvm::InitializeAllAsmParsers();
	llvm::InitializeAllDisassemblers();
}

LLVMLifter::LLVMLifter()
{
	system_arch = "";
	x86_target = 0;
}

void LLVMLifter::SetSystemArch(string system_arch)
{
	this->system_arch = system_arch;

	x86_target = 0;
	for(TargetRegistry::iterator it = TargetRegistry::begin(), e = TargetRegistry::end(); it != e; it++)
	{
		const Target  &t = *it;
		if(string(t.getName()) == system_arch)
		{
			x86_target = &t;
			break;
		}
	}

}

int LLVMLifter::BinDescend(string in_filename)
{
	//llvm::Triple *triple;

	if(!x86_target)
	{
		outs() << "No target.\n";
		return 0;
	}

	if(!system_arch.compare("x86-64"))
	{
		triple = new Triple("x86_64-pc-linux-gnu"); //DEFAULT_TRIPLE_X64);
	}
	else
	{
		triple = new Triple(DEFAULT_TRIPLE);
	}


	ExternalFunctionMap funcs(triple->getTriple());

	try
	{
		for(unsigned i = 0; i < python::len(func_maps); i++)
		{
			funcs.parseMap(python::extract<string>(func_maps[i]));
		}
	}
	catch (LErr &l)
	{
		cerr << "Exception while parsing external map:\n" << l.what() << std::endl;
		return -2;
	}


	string prior_knowledge = ""; // TODO

	if(prior_knowledge == "")
	{
		outs() << "Disassembly not guided by outside facts.\n"; //\nUse :'" << argv[0] << "-p <protobuff>' to feed information to guide the disassembly\n";
	}


	//open the binary input file
	ExecutableContainer *exc = NULL;


	try
	{
		exc = ExecutableContainer::open(in_filename, x86_target, prior_knowledge);
	}
	catch (LErr &l)
	{
		errs() << "Could not open: " << in_filename << ", reason: " << l.what() << "\n";
		return -1;
	}
	catch (...)
	{
		errs() << "Could not open: " << in_filename << "\n";
		return -1;
	}



	//sanity
	if(python::len(entry_symbols) == 0 && python::len(entry_points) == 0)
	{
		std::uint64_t file_ep;
		// maybe this file format specifies an entry point?
		if(false == exc->getEntryPoint(file_ep))
		{
			//We don't know which entry point to use!
			llvm::errs() << "Could not identify an entry point for: [" << in_filename << "].\n";
			llvm::errs() << "You must manually specify at least one entry point. Use either -entry-symbol or -e.\n";
			return -1;
		}
	}


	if(exc->is_open())
	{
		//convert to native CFG
		//NativeModulePtr m;
		try
		{
			module = MakeNativeModule(exc, funcs);
		}
		catch(LErr &l)
		{
			outs() << "Failure to make module: " << l.what() << "\n";
			return -1;
		}

		//string outS = dumpProtoBuf(module);

		outs() << "Finished.\n";

		/*if(m)
		{
			//write out to protobuf
			if(outS.size() > 0) {
				filesystem::path p;
				if (OutputFilename == "") {
					//write out to file, but, make the file name
					//the same as the input file name with the ext
					//removed and replaced with .cfg
					p = filesystem::path(string(InputFilename));
					p = p.replace_extension(".cfg");
				}
				else {
					p = filesystem::path(string(OutputFilename));
				}

				FILE  *out = fopen(p.string().c_str(), "wb");
				if(out) {
					fwrite(outS.c_str(), 1, outS.size(), out);
					fclose(out);
				} else {
					//report error
					outs() << "Could not open " << p.string() << "\n";
				}
			}
		}*/

	}
	else
	{
		outs() << "Could not open executable module " << in_filename << "\n";
	}

	return 0;
}



NativeModulePtr LLVMLifter::MakeNativeModule(ExecutableContainer *exc, ExternalFunctionMap &funcs)
{
	// these entry points are valid function entry points, but
	// they will not be externally visible
	list<VA>          entryPoints;

	// these will be externally visible
	vector<NativeModule::EntrySymbol>     entrySymbols;

	list<NativeFunctionPtr> recoveredFuncs;
	LLVMByteDecoder         byteDec(exc->target);

	for(unsigned i = 0; i < python::len(entry_points); i++)
	{
		//get the entry point from the command line
		std::uint64_t      tmp = 0;
		std::string ep = python::extract<string>(entry_points[i]);
		stringstream  ss;
		if(ep.size() > 2 && ep[0] == '0' && ep[1] == 'x')
			ss << hex << ep;
		else
			ss << ep;

		ss >> tmp;
		//entryPoints.push_back(((VA)tmp));
		entryPoints.push_back(tmp);
		entrySymbols.push_back(NativeModule::EntrySymbol(tmp));
	}

	if(python::len(entry_symbols))
	{
		//have to look this symbol up from the ExecutableContainer
		list<pair<string, VA> > t;
		if(!exc->get_exports(t))
		{
			throw LErr(__LINE__, __FILE__, "Could not parse export table");
		}

		for(unsigned i = 0; i < python::len(entry_symbols); i++)
		{
			std::string es = python::extract<string>(entry_symbols[i]);

			for(list<pair<string, VA> >::iterator it = t.begin(), e = t.end();
				it != e;
				++it)
			{
				if(it->first == es) {
					entryPoints.push_back(it->second);
					entrySymbols.push_back(
							NativeModule::EntrySymbol(
									it->first,
									it->second));
					break;
				}
			}
		}
	}

	if(ignore_native_entry_points == false)
	{
		//get entry points from the file too
		list<pair<string, std::uint64_t> > tmp;
		exc->get_exports(tmp);

		for(list<pair<string, std::uint64_t> >::iterator it = tmp.begin(), e = tmp.end(); it != e; ++it)
		{
			entrySymbols.push_back(
					NativeModule::EntrySymbol(
							it->first,
							it->second));
			entryPoints.push_back(it->second);
		}

		std::uint64_t file_ep;
		if(exc->getEntryPoint(file_ep)) {
			entryPoints.push_back(file_ep);
		}
	}


	if(entryPoints.size() == 0)
	{
		throw LErr(__LINE__, __FILE__, "No good entry points found or supplied");
	}

	if(debug_mode)
	{
		addDataEntryPoints(exc, entryPoints, llvm::dbgs());
	}
	else
	{
		addDataEntryPoints(exc, entryPoints, nulls());
	}

	set<VA> visited;
	//now, get functions for these entry points with this executable
	//context
	outs() << "We have " << entryPoints.size() << " entry points\n";

	for(list<std::uint64_t>::iterator it = entryPoints.begin(), e = entryPoints.end(); it != e; ++it)
	{
		list<NativeFunctionPtr> tmp;
		if(debug_mode)
		{
			tmp = getFuncs(exc, byteDec, visited, *it, funcs, llvm::dbgs());
		}
		else
		{
			tmp = getFuncs(exc, byteDec, visited, *it, funcs, nulls());
		}

		recoveredFuncs.insert(recoveredFuncs.end(), tmp.begin(), tmp.end());

	}

	//add the recovered functions to a new NativeModule
	NativeModulePtr m(new NativeModule(exc->name(), recoveredFuncs, NULL));

	// add exported entry points
	for(vector<NativeModule::EntrySymbol>::const_iterator it_es = entrySymbols.begin(); it_es != entrySymbols.end(); it_es++)
	{
		m->addEntryPoint(*it_es);
	}

	//add what data we can discern is required to m
	//data is required if it is a data section from exc
	vector<ExecutableContainer::SectionDesc>  secs;
	if(!exc->get_sections(secs)) throw LErr(__LINE__, __FILE__, "Sections");
	for(vector<ExecutableContainer::SectionDesc>::iterator it = secs.begin(),
				e = secs.end();
		it != e;
		++it)
	{
		ExecutableContainer::SectionDesc  s = *it;

		if(s.type == ExecutableContainer::DataSection) {
			//add to m
			DataSection ds = processDataSection(exc, s);
			// make sure data section is not empty
			if(ds.getBase() != DataSection::NO_BASE) {
				outs() << "Adding data section: "
					   << to_string<VA>(ds.getBase(), hex) << " - "
					   << to_string<VA>(ds.getBase()+ds.getSize(), hex) << "\n";
				ds.setReadOnly(s.read_only);
				m->addDataSection(ds);
			}
		}
	}

	//add the external function references
	addExterns(recoveredFuncs, m);

	//done
	return m;
}




// cfg_to_bc


llvm::Module  *getLLVMModule(string name, const std::string &triple)
{
	llvm::Module  *M = new llvm::Module(name, llvm::getGlobalContext());
	llvm::Triple TT = llvm::Triple(triple);
	M->setTargetTriple(triple);


	std::string layout;

	if(TT.getOS() == llvm::Triple::Win32) {
		if(TT.getArch() == llvm::Triple::x86) {
			layout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-f80:128:128-v64:64:64-v128:128:128-a0:0:64-f80:32:32-n8:16:32-S32";
		} else if(TT.getArch() == llvm::Triple::x86_64) {
			layout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128" ;
		} else {
			std::cerr << "Unsupported arch in triple: " << triple << "\n";
			return nullptr;
		}
	} else if (TT.getOS() == llvm::Triple::Linux) {
		if(TT.getArch() == llvm::Triple::x86) {
			layout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-f32:32:32-f64:32:64-v64:64:64-v128:128:128-a0:0:64-f80:32:32-n8:16:32-S128";
		} else if(TT.getArch() == llvm::Triple::x86_64) {
			// x86_64-linux-gnu
			layout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128";
		} else {
			std::cerr << "Unsupported arch in triple: " << triple << "\n";
			return nullptr;
		}
	} else {
		std::cerr << "Unsupported OS in triple: " << triple << "\n";
		return nullptr;
	}

	M->setDataLayout(layout);

	doGlobalInit(M);

	return M;
}




static VA string_to_int(const std::string &s) {
	VA ret;
	if(s.size() > 1 && (s[1] == 'x' || s[1] == 'X')) {
		ret = strtol(s.c_str(), NULL, 16);
	} else {
		ret = strtol(s.c_str(), NULL, 10);
	}

	// sanity check
	if( ret == 0 && s[0] != '0') {
		throw LErr(__LINE__, __FILE__, "Could not convert string to int: "+s);
	}

	return ret;
}

static bool driverArgsToDriver(const string &args, DriverEntry &new_d) {

	boost::char_separator<char> sep(",");
	boost::tokenizer<boost::char_separator<char> >  toks(args, sep);
	vector<string>  vtok;
	BOOST_FOREACH(const string &t, toks) {
					vtok.push_back(t);
				}

	if(vtok.size() >= 7) {
		return false;
	}

	// take name as is
	new_d.name = vtok[0];

	string sym_or_ep = vtok[1];
	char fl = sym_or_ep[0];
	// if the first letter is 0-9, assume its entry address
	if(fl >= '0' && fl <= '9') {
		new_d.sym = "";
		new_d.ep = string_to_int(sym_or_ep);
	} else {
		// if its not, assume entry symbol
		new_d.ep = 0;
		new_d.sym = sym_or_ep;
	}

	// check if this driver is raw
	boost::algorithm::to_lower(vtok[2]);
	if(vtok[2] == "raw") {
		new_d.is_raw = true;
	} else {
		// if not, parse number of arguments
		new_d.is_raw = false;
		new_d.argc = (int)string_to_int(vtok[2]);
	}

	// check if this "returns" or "noreturns"
	boost::algorithm::to_lower(vtok[3]);
	if(vtok[3] == "return") {
		new_d.returns = true;
	} else if (vtok[3] == "noreturn") {
		new_d.returns = false;
	} else {
		return false;
	}

	if(vtok[4] == "F") {
		new_d.cconv = ExternalCodeRef::FastCall;
	} else if(vtok[4] == "C") {
		new_d.cconv = ExternalCodeRef::CallerCleanup;
	} else if(vtok[4] == "E") {
		// default to stdcall
		new_d.cconv = ExternalCodeRef::CalleeCleanup;
	} else if(vtok[4] == "S") {
		// default to stdcall
		new_d.cconv = ExternalCodeRef::X86_64_SysV;
	} else if(vtok[4] == "W") {
		new_d.cconv = ExternalCodeRef::X86_64_Win64;
	}
	else {
		return false;
	}

	if(vtok.size() >= 6){
		boost::algorithm::to_upper(vtok[5]);
		new_d.sign = vtok[5];
	}

	return true;
}


static bool findSymInModule(NativeModulePtr mod, const std::string &sym, VA &ep) {
	const vector<NativeModule::EntrySymbol> &syms = mod->getEntryPoints();
	for(vector<NativeModule::EntrySymbol>::const_iterator itr = syms.begin();
		itr != syms.end();
		itr++ )
	{
		if(itr->getName() == sym) {
			ep = itr->getAddr();
			return true;
		}
	}

	ep = 0;
	return false;
}

// check if an entry point (to_find) is in the list of possible
// entry points for this module
static bool findEPInModule(NativeModulePtr mod, VA to_find, VA &ep) {
	const vector<NativeModule::EntrySymbol> &syms = mod->getEntryPoints();
	for(vector<NativeModule::EntrySymbol>::const_iterator itr = syms.begin();
		itr != syms.end();
		itr++ )
	{
		if(itr->getAddr() == to_find) {
			ep = to_find;
			return true;
		}
	}

	ep = 0;
	return false;
}

static bool haveDriverFor(const std::vector<DriverEntry> &drvs,
						  const std::string &epname )
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


int LLVMLifter::CFGToBC()
{
	cout << "Triple: " << triple->getTriple() << endl;


	// parse driver args
	/*vector<DriverEntry> drivers;
	try
	{
		for(unsigned i = 0; i < python::len(drivers_args); i++)
		{
			string driverArgs = python::extract<string>(drivers_args[i]);
			DriverEntry d;
			if(!driverArgsToDriver(driverArgs, d))
			{
				llvm::errs() << "Could not parse driver argument: " << driverArgs << "\n";
				return 0;
			}
			drivers.push_back(d);
		}
	}
	catch(std::exception &e)
	{
		cout << "error: " << endl << e.what() << endl;
		return 0;
	}*/


	vector<DriverEntry> drivers;

	for(unsigned int i=0; i<python::len(driver_entries); i++)
		drivers.push_back(python::extract<DriverEntry>(driver_entries[i]));




	//reproduce NativeModule from CFG input argument
	/*cout << "Reading module ..." << endl;
	NativeModulePtr mod = readModule(InputFilename, ProtoBuff, list<VA>(), x86Target);
	if(mod == NULL) {
		cerr << "Could not process input module: " << InputFilename << std::endl;
		return -2;
	}*/


	if(!module)
	{
		outs() << "No module.\n";
		return 0;
	}


	// set native module target
	cout << "Setting initial triples..." << endl;
	module->setTarget(x86_target);
	module->setTargetTriple(triple->getTriple());

	const std::vector<NativeModule::EntrySymbol>& native_eps = module->getEntryPoints();
	std::vector<NativeModule::EntrySymbol>::const_iterator natep_it;
	cout << "Looking at entry points..."  << endl;
	for( natep_it = native_eps.begin();
		 natep_it != native_eps.end();
		 natep_it++)
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
		return -1;
	}

	/*if(!module)
	{
		cout << "Unable to read module from CFG" << endl;
		return -1;
	}*/

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
	llvm::Module  *M = getLLVMModule(module->name(), triple->getTriple());

	if(!M)
	{
		cout << "Unable to get LLVM module" << endl;
		return -1;
	}

	bool  modResult = false;

	try {
		cout << "Converting to LLVM..."  << endl;
		modResult = natModToModule(module, M, outs());
	} catch(std::exception &e) {
		cout << "error: " << endl << e.what() << endl;
		return -1;
	}

	if( modResult )
	{
		try {
			for(vector<DriverEntry>::const_iterator itr = drivers.begin();
				itr != drivers.end();
				itr++)
			{

				VA ep = 0;

				// if this is a symbolic reference, look it up
				if(itr->ep == 0 && itr->sym != "") {
					if(!findSymInModule(module, itr->sym, ep)) {
						llvm::errs() << "Could not find entry point: " << itr->sym << "; aborting\n";
						return -1;
					}

				} else {
					// if this is an address reference, make sure its
					// a valid entry point
					if(!findEPInModule(module, itr->ep, ep)) {
						llvm::errs() << "Could not find entry address: " <<
									 to_string<VA>(itr->ep, hex) << "; aborting\n";
						return -1;
					}
				}

				cout << "Adding entry point: " << itr->name << std::endl;

				if(itr->is_raw == true)
				{
					if(module->is64Bit()) x86_64::addEntryPointDriverRaw(M, itr->name, ep);
					else x86::addEntryPointDriverRaw(M, itr->name, ep);
				}
				else
				{
					if(module->is64Bit()) {
						x86_64::addEntryPointDriver(M, itr->name, ep, itr->argc, itr->returns, outs(), itr->cconv, itr->sign);
					} else {
						x86::addEntryPointDriver(M, itr->name, ep, itr->argc, itr->returns, outs(), itr->cconv);
					}

				}

			} // for vector<DriverEntry>




			bool EnablePostAnalysis = true; // TODO

			if(EnablePostAnalysis) {
				cout << "Doing post analysis passes...\n";
				doPostAnalysis(module, M);
			} else {
				cout << "NOT doing post analysis passes.\n";
			}


			bool ShouldVerify = true; // TODO

			// will abort if verification fails
			if(ShouldVerify && llvm::verifyModule(*M, &errs())) {
				cerr << "Could not verify module!\n";
				return -1;
			}

			M->addModuleFlag(llvm::Module::Error, "Debug Info Version", DEBUG_METADATA_VERSION);
			M->addModuleFlag(llvm::Module::Error, "Dwarf Version", 3);

			/*string                  errorInfo;
			llvm::tool_output_file  Out(OutputFilename.c_str(),
										errorInfo,
										sys::fs::F_None);
			WriteBitcodeToFile(M, Out.os());
			Out.keep();*/


			//string bitcode_data;
			raw_string_ostream os(bitcode_data);
			WriteBitcodeToFile(M, os);
			return 1;
		}
		catch(std::exception &e)
		{
			cout << "error: " << endl << e.what() << endl;
			return 0;
		}
	}
	else
	{
		cout << "Failure to convert to LLVM module!" << endl;
		return 0;
	}
}


