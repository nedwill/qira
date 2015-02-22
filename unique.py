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

if len(sys.argv) != 2:
    print "usage: {} [directory]".format(sys.argv[0])
    sys.exit()

#based on get_instruction_flow from qira_analysis
def get_unique_instructions(trace, program):
  start = time.time()
  ret = set()
  for i in range(trace.db.get_minclnum(), trace.db.get_maxclnum()):
    r = trace.db.fetch_changes_by_clnum(i, 1)
    if len(r) != 1:
      continue

    # this will trigger the disassembly
    instr = program.static[r[0]['address']]['instruction']
    #print instr.raw.encode("hex")
    ret.add(instr.raw.encode("hex"))
    if (time.time() - start) > 0.01:
      time.sleep(0.01)
      start = time.time()

  return ret

fn = sys.argv[1]

#from my static testing code
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

file_list = get_file_list(sys.argv[1])[:5]

d = {}
for fn in file_list:
  ### tim stuff
  program = qira_program.Program(fn)
  program.clear()
  program.execqira()
  time.sleep(.1) # we have to wait for the trace :/
  program.add_trace(qira_config.TRACE_FILE_BASE+"0", 0, run_analysis=False)
  trace = program.traces[0]
  trace.read_strace_file()
  time.sleep(1) # we have to wait for qiradb :/
  ###
  short_fn = fn.split("/")[-1]
  d[short_fn] = get_unique_instructions(trace, program)
print d
