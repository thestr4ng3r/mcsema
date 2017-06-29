
from subprocess import call
from mcsema_disass.radare2 import get_cfg


#cfg_recover = get_cfg.Radare2CFGRecover()
#cfg_recover.recover_cfg("/bin/ls", "ls.cfg", "ls_text.cfg", ["main"])

ida_cmd = "/home/florian/bin/idaq64 -S\"../tools/mcsema_disass/ida/get_cfg.py --output ls_ida_text.cfg --log_file /dev/null --arch amd64 --os linux --entrypoint main\" ls"
call(ida_cmd, shell=True)

#call("../bin/mcsema-lift -arch=amd64 -os=linux -cfg=ls_ida.cfg -entrypoint=main -output=ls.bc", shell=True)
