from trace import *
import concrete_execution

def validate_bil(program):
  program, trace = process_program(program)
  flow = qira_analysis.get_instruction_flow(trace, program, trace.db.get_minclnum(), trace.db.get_maxclnum())
  errors, warnings = concrete_execution.validate_bil(program, flow)
  return errors, warnings

def print_issue(i):
  print str(i.__class__) + ":", issue.message
  print "\tClnum: ", issue.clnum
  print "\tInstruction: ", issue.insn
  print "-"*70

@processify
def validate_process(fn):
  try:
    program = qira_program.Program(fn)
  except ELFError:
    print "{} skipping non-ELF `{}'...".format(warn, short_fn)
    return [], []
  return validate_bil(program)

#actually use our own process_files here to bail out when we see an error
def process_files_stop(file_list):
  for i,fn in enumerate(file_list):
    short_fn = fn.split("/")[-1]
    print "{} [{}/{}] done, checking {}...".format(star_blue, i+1, len(file_list), short_fn)
    try:
      errors, warnings = validate_process(fn)
      if len(errors) > 0:
        print "{} Issues found in {}:".format(warn, fn)
        for issue in errors:
          print_issue(issue)
        exit()
    except Exception as exn:
      print "{} processing {} failed".format(fail, short_fn), type(exn).__name__, exn
      print traceback.format_exc()
      exit()

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Check BIL over a corpus of input files.")
  parser.add_argument("tests", help="input file or folder (checked recursively)")
  parser.add_argument("--stop", action="store_true", help="stop on the first BIL error")
  args = parser.parse_args()
  file_list = get_file_list(args.tests)

  if args.stop:
    process_files_stop(file_list)
  else:
    d, failed = process_files(file_list, validate_bil)

    if len(failed) > 0:
      print "{} Failed to process:".format(fail)," ".join(failed)

    for fn,(errors, warnings) in d.iteritems():
      if len(errors) > 0:
        print "{} Issues found in {}:".format(warn, fn)
        for issue in errors:#+warnings:
          print_issue(issue)
