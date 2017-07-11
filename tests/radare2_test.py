
from subprocess import call
from mcsema_disass.radare2 import get_cfg
import sys

test_ida = False
if len(sys.argv) > 1:
	if sys.argv[1] == "ida":
		test_ida = True


binary_file = "radare2/test1"

cfg_recover = get_cfg.Radare2CFGRecover()
cfg_recover.recover_cfg("radare2/test1", "test1.cfg", "test1_text.cfg", ["main"])

if test_ida:
	ida_cmd = "/home/florian/bin/idaq64 -S\"Z:/home/florian/hdd/dev/mcsema/tools/mcsema_disass/ida/get_cfg.py --output test1_ida_text.cfg --log_file /dev/null --arch amd64 --os linux --entrypoint main\" " + binary_file
	call(ida_cmd, shell=True)

#call("../bin/mcsema-lift -arch=amd64 -os=linux -cfg=ls_ida.cfg -entrypoint=main -output=ls.bc", shell=True)
