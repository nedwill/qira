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

#based on get_instruction_flow from qira_analysis
#arm flag tells us whether to disasm or not, autodetect from ELF?
def get_unique_instructions(trace, program, arm=True):
  start = time.time()
  ret = set()
  for i in range(trace.db.get_minclnum(), trace.db.get_maxclnum()):
    r = trace.db.fetch_changes_by_clnum(i, 1)
    if len(r) != 1:
      continue

    # this will trigger the disassembly
    if arm:
      if program.static[r[0]['address']]['arch'] == "thumb":
        instr_hex = program.static.memory(r[0]['address'], 0x02)
      else:
        instr_hex = program.static.memory(r[0]['address'], 0x04)
    else:
      instr_hex = program.static[r[0]['address']]['instruction'].raw.encode("hex")
    #print "arch",program.static[r[0]['address']]['arch']
    #print instr.raw.encode("hex")
    ret.add(instr_hex)
    if (time.time() - start) > 0.01:
      time.sleep(0.01)
      start = time.time()

  return ret

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

def process_fn(program):
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
  instructions = get_unique_instructions(trace, program)
  return instructions

def get_largest_name(d):
  assert len(d) > 0
  current_max_fn = None
  current_max_uniq_ins = 0
  for fn,unique_ins_set in d.iteritems():
    current_uniq_ins = len(unique_ins_set)
    if current_uniq_ins > current_max_uniq_ins:
      current_max_fn = fn
      current_max_uniq_ins = current_uniq_ins
  assert type(current_max_fn) is str #we set the fn name, not None
  return current_max_fn

def get_unique_instruction_dict(file_list):
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
        d[fn] = process_fn(program)
      except Exception as exn:
        print "{} processing {} failed".format(fail, short_fn), type(exn).__name__, exn
        print traceback.format_exc()
        failed.add(fn)
    return d, failed

def get_min_set(folder_name):
    file_list = get_file_list(folder_name)
    d, failed = get_unique_instruction_dict(file_list)
    if len(d) == 0:
        print "No instructions executed."
        sys.exit()
    d_orig = d
    #weird unpacking here. can probably do better
    all_elements = set.union(*[v for (_,v) in d_orig.iteritems()])
    #use this to check that everything is hit at the end

    min_set = set()
    while len(d) > 0:
      print "{} {} files remaining in min_set selection...".format(star_blue, len(d))
      largest_name = get_largest_name(d)
      min_set.add(largest_name)
      largest_elements = d[largest_name]
      d_new = {}
      for k,v in d.iteritems():
        if k == largest_name:
          continue
        v_new = v.difference(largest_elements)
        if len(v_new) > 0:
          d_new[k] = v_new
      d = d_new

    #check that we have all the instructions in the min_set
    new_all_elements = set.union(*[d_orig[k] for k in min_set])
    assert all_elements == new_all_elements

    print "{} There was a total reduction from {} input files to {} output files.".format(ok_green, len(d_orig), len(min_set))
    if len(failed) > 0:
        print "{} An error occurred when processing the following {} files:".format(warn, len(failed)),failed
    return (min_set, failed)

def move_files(min_set, failed, dest_folder):
    call(["mkdir", "-p", dest_folder])
    print "move files called"
    for fn in min_set | failed:
        print "moving",fn
        short_fn = fn.split("/")[-1]
        dest = os.path.join(dest_folder,short_fn)
        #print " ".join(["cp", fn, dest])
        call(["cp", fn, dest])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Minimize test corpus to cover all instructions.")
    parser.add_argument("input_folder", help="input folder")
    parser.add_argument("output_folder", help="output folder")
    args = parser.parse_args()
    print args.input_folder, args.output_folder
    min_set, failed = get_min_set(args.input_folder)
    move_files(min_set, failed, args.output_folder)
