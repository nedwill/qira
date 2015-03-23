from trace import *

#min set implementation where we minimize unique instructions
#works best with static off in qira_config.py

#based on get_instruction_flow from qira_analysis
#arm flag tells us whether to disasm or not, autodetect from ELF?
@processify
def get_unique_instructions(program, arm=True):
  program, trace = process_program(program)
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
    ret.add(instr_hex)
    if (time.time() - start) > 0.01:
      time.sleep(0.01)
      start = time.time()

  return ret

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
  return process_files(file_list, get_unique_instructions)

def get_min_set(folder_name):
    file_list = get_file_list(folder_name)
    d, failed = get_unique_instruction_dict(file_list)
    if len(d) == 0:
        print "No instructions executed."
        sys.exit()
    d_orig = d
    #print d_orig
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
    print "copying",fn
    short_fn = fn.split("/")[-1]
    dest = os.path.join(dest_folder,short_fn)
    call(["cp", fn, dest])

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Minimize test corpus to cover all instructions.")
  parser.add_argument("input_folder", help="input folder")
  parser.add_argument("output_folder", help="output folder")
  args = parser.parse_args()
  min_set, failed = get_min_set(args.input_folder)
  move_files(min_set, failed, args.output_folder)
