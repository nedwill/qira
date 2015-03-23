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

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Check BIL over a corpus of input files.")
  parser.add_argument("tests", help="input file or folder (checked recursively)")
  args = parser.parse_args()
  file_list = get_file_list(args.tests)

  d, failed = process_files(file_list, validate_bil)

  if len(failed) > 0:
    print "{} Failed to process:".format(fail)," ".join(failed)

  for fn,(errors, warnings) in d.iteritems():
    print "{} Issues found in {}:".format(warn, fn)
    for issue in errors:#+warnings:
      print_issue(issue)
