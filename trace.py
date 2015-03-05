#!/usr/bin/env python2.7
#script heavily based on one written by Tim Becker (props!)

#qira needs to be installed with BAP. also you need to run
#source venv/bin/activate and eval $(opam config env)
import sys
sys.path.append("middleware/")
import time
import os
import qira_program, qira_analysis, qira_config
from glob import glob
import gc
import traceback
import argparse
from subprocess import call

#modified to be used here from qira_program so it doesn't trigger disasm
def read_asm_file(self):
  if os.name == "nt":
    return
  dat = self.qira_asm_file.read()
  if len(dat) == 0:
    return
  cnt = 0
  for d in dat.split("\n"):
    thumb = False
    if len(d) == 0:
      continue
    # hacks
    try:
      if self.fb == 0x28:
        #thumb bit in front
        addr = int(d.split(" ")[0][1:].strip(":"), 16)
      else:
        addr = int(d.split(" ")[0].strip(":"), 16)
    except:
      continue
    if self.fb == 0x28:
      thumb_flag = d[0]
      if thumb_flag == 't':
        thumb = True
        # override the arch since it's thumb
        self.static[addr]['arch'] = "thumb"
      elif thumb_flag == 'n':
        thumb = False
      else:
        #print "*** Invalid thumb flag at beginning of instruction"
        pass
      inst = d[d.rfind("  ")+2:]
    elif self.fb == 0xb7:   # aarch64
      inst = d[d.rfind("     ")+5:]
    else:
      inst = d[d.find(":")+3:]
    cnt += 1

#from my static testing code
######
class bcolors(object):
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKGREEN = '\033[92m'
  WARNING = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'

ok_green  = bcolors.OKGREEN + "[+]" + bcolors.ENDC
ok_blue   = bcolors.OKBLUE  + "[+]" + bcolors.ENDC
star_blue = bcolors.OKBLUE  + "[*]" + bcolors.ENDC
warn      = bcolors.WARNING + "[-]" + bcolors.ENDC
fail      = bcolors.FAIL    + "[!]" + bcolors.ENDC

def get_file_list(loc, recursive=True):
  fns = []
  if recursive:
    for fn in glob(loc):
      if os.path.isdir(fn):
        for root, dirnames, filenames in os.walk(fn):
          fns += [os.path.join(root, f) for f in filenames]
      else:
        fns.append(fn)
  else:
    for fn in glob(loc):
      if not os.path.isdir(fn):
        fns.append(fn)
  return fns
######

from elftools.common.exceptions import ELFError

def process_program(program):
  program.clear()
  program.execqira()
  time.sleep(.1) # we have to wait for the trace :/
  program.add_trace(qira_config.TRACE_FILE_BASE+"0", 0, run_analysis=False)
  trace = program.traces[0]
  trace.read_strace_file()
  time.sleep(1) # we have to wait for qiradb :/
  #while not trace.db.did_update(): #is this better? from qira_analysis.py
  #  time.sleep(0.1)
  program.qira_asm_file = open("/tmp/qira_asm", "r")
  read_asm_file(program) #so we get thumb flag if arm
  return program, trace

def process_files(file_list, f):
  d = {}
  failed = set()
  for i,fn in enumerate(file_list):
    short_fn = fn.split("/")[-1]
    print "{} [{}/{}] files initally processed...".format(star_blue, i+1, len(file_list))
    try:
      program = qira_program.Program(fn)
    except ELFError:
      print "{} skipping non-ELF `{}'...".format(warn, short_fn)
      continue
    try:
      d[fn] = f(program)
    except Exception as exn:
      print "{} processing {} failed".format(fail, short_fn), type(exn).__name__, exn
      print traceback.format_exc()
      failed.add(fn)
  return d, failed
