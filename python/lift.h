//
// Created by florian on 14.03.17.
//

#ifndef MCSEMA_PYTHON_LIFT_H
#define MCSEMA_PYTHON_LIFT_H

#include <set>

#include "mcsema/CFG/CFG.h"

//translate a NativeModule into an LLVM Module
void RenameLiftedFunctions(NativeModulePtr mod, llvm::Module *M,
						   const std::set<VA> &entry_point_pcs);

bool LiftCodeIntoModule(NativeModulePtr natMod, llvm::Module *M, bool ignore_unsupported_insts, bool add_breakpoints, bool add_tracer);

#endif
