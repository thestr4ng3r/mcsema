
from sys import argv
import subprocess
import os

import mcsema
import cfg_ida


def begin(noclean=False):
	clean_files = "*.o *.ll *.bc *.idb demo_driver"

	if len(argv) > 1:
		if argv[1] == "clean":
			subprocess.call("rm -fv " + clean_files, shell=True)
			quit()


	if not noclean:
		subprocess.call("rm -f " + clean_files, shell=True)


def cfg_generator(input_file, system_arch):
	if system_arch == "x86-64":
		ida_env = "IDA64_EXEC"
	else:
		ida_env = "IDA_EXEC"

	ida_exec = os.getenv(ida_env)

	if ida_exec:
		print("Using IDA \"" + ida_exec + "\" for CFG generation.")
		return cfg_ida.IDACFGGenerator(ida_exec, "../../../mc-sema/bin_descend/get_cfg.py", input_file)
	else:
		print("---")
		print("IDA Pro executable has not been found.")
		print("To use IDA for CFG recovery, specify the path to idaq and idaq64 in the environment variables IDA_EXEC and IDA64_EXEC.")
		print("----")
		print("Using bin_descend for CFG generation.")
		bin_descend = mcsema.BinDescend(input_file)
		bin_descend.arch = system_arch
		return bin_descend

def call(cmd):
	print("-- %s" % cmd)
	r = subprocess.check_call(cmd, shell=True)
	return r
