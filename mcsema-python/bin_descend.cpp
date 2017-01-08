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
#include "llvm/Support/Debug.h"
#include "cfg_recover.h"
#include <toLLVM.h>
#include <raiseX86.h>
#include "../mc-sema/common/Defaults.h"

#include <llvm/IR/Verifier.h>

#include "bin_descend.h"

using namespace std;
using namespace boost;
using namespace llvm;

BinDescend::BinDescend()
{
	system_arch = "";
	x86_target = 0;
}

void BinDescend::SetSystemArch(string system_arch)
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

int BinDescend::Execute(string in_filename)
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



NativeModulePtr BinDescend::MakeNativeModule(ExecutableContainer *exc, ExternalFunctionMap &funcs)
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
		list<pair<string, VA>> tmp;
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


