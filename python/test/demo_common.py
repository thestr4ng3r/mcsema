
import sys
import os.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
from sys import argv
import subprocess
from os import getenv

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


def cfg_generator(input_file, arch, os):
	if arch == "amd64":
		ida_env = "IDA64_EXEC"
	else:
		ida_env = "IDA_EXEC"

	ida_exec = getenv(ida_env)

	if ida_exec:
		print("Using IDA \"" + ida_exec + "\" for CFG generation.")
		return cfg_ida.IDACFGGenerator(ida_exec, "../../../tools/mcsema_disass/ida/get_cfg.py", input_file, arch, os)
	else:
		print("---")
		print("IDA Pro executable has not been found.")
		print("----")
		return None

def call(cmd):
	print("-- %s" % cmd)
	r = subprocess.check_call(cmd, shell=True)
	return r
