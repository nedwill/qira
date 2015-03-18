#!/usr/bin/env python2.7

from bap import bil
from functools import partial
from model import BapInsn
from bitvector import ConcreteBitVector
import collections

class Memory:
  def __init__(self, fetch_mem, initial=None):
    self.fetch_mem = fetch_mem
    self.memory = {} if initial is None else initial

  def get_mem(self, addr, size, little_endian=True):
    addr = int(addr)
    result = "".join([self[address] for address in range(addr, addr+size)])
    if little_endian: result = result[::-1]
    return result

  def set_mem(self, addr, size, val, little_endian=True):
    for i in range(size):
      addr = int(addr)
      shift = i if little_endian else size-i-1
      byteval = (val >> shift*8) & 0xff
      self[addr+i] = chr(byteval)

  def items(self):
    return self.memory.items()

  def __setitem__(self, addr, val):
    self.memory[addr] = val

  def __getitem__(self, addr):
    if addr not in self.memory:
      self.memory[addr] = self.fetch_mem(addr, 1)

    return self.memory[addr]

  def __str__(self):
    return "".join(["%x : %x\n" % (addr, ord(val)) for addr, val in self.memory.items()])

class State:
  def __init__(self, variables, get_mem, initial_mem=None):
    self.variables = variables
    self.memory = Memory(get_mem, initial_mem)

  def get_mem(self, addr, size, little_endian=True):
    return self.memory.get_mem(addr, size, little_endian)

  def set_mem(self, addr, size, val, little_endian=True):
    return self.memory.set_mem(addr, size, val, little_endian)

  def __getitem__(self, name):
    if isinstance(name, str):
      return self.variables[name]
    else:
      return self.memory[name]

  def __setitem__(self, name, val):
    if isinstance(name, str):
      self.variables[name] = val
    else:
      self.memory[name] = val

  def __str__(self):
    return str(self.variables)


def eval_bil_expr(expr, state):
  """
  Warning: Can modify state
  """

  def eval_expr(expr):
    """
    Helper function to prevent passing state recursively every time
    """
    if isinstance(expr, bil.Load):
      addr = eval_expr(expr.idx)
      size = expr.size
      mem = state.get_mem(addr, size / 8, isinstance(expr.endian, bil.LittleEndian))
      return ConcreteBitVector(size, int(mem.encode('hex'), 16))
    elif isinstance(expr, bil.Store):
      addr = eval_expr(expr.idx)
      val = eval_expr(expr.value)
      size = expr.size
      state.set_mem(addr, size / 8, val, isinstance(expr.endian, bil.LittleEndian))
    elif isinstance(expr, bil.Var):
      return state[expr.name]
    elif isinstance(expr, bil.Int):
      return ConcreteBitVector(expr.size, expr.value)
    elif isinstance(expr, bil.Let):
      tmp = state.get(expr.var.name, None)
      state[expr.var.name] = eval_expr(expr.value)
      result = eval_expr(expr.expr)
      if tmp is None:
        state.remove(expr.var.name)
      else:
        state[expr.var.name] = tmp
      return result
    elif isinstance(expr, bil.PLUS):
      return eval_expr(expr.lhs) + eval_expr(expr.rhs)
    elif isinstance(expr, bil.MINUS):
      return eval_expr(expr.lhs) - eval_expr(expr.rhs)
    elif isinstance(expr, bil.TIMES):
      return eval_expr(expr.lhs) * eval_expr(expr.rhs)
    elif isinstance(expr, bil.DIVIDE):
      return eval_expr(expr.lhs) / eval_expr(expr.rhs)
    elif isinstance(expr, bil.SDIVIDE):
      return eval_expr(expr.lhs) / eval_expr(expr.rhs)
    elif isinstance(expr, bil.MOD):
      return eval_expr(expr.lhs) % eval_expr(expr.rhs)
    elif isinstance(expr, bil.SMOD):
      return eval_expr(expr.lhs) % eval_expr(expr.rhs)
    elif isinstance(expr, bil.LSHIFT):
      return eval_expr(expr.lhs) << eval_expr(expr.rhs)
    elif isinstance(expr, bil.RSHIFT):
      shift = eval_expr(expr.rhs)
      var = eval_expr(expr.lhs)
      return var.lrshift(shift)
    elif isinstance(expr, bil.ARSHIFT):
      return eval_expr(expr.lhs) >> eval_expr(expr.rhs)
    elif isinstance(expr, bil.AND):
      return eval_expr(expr.lhs) & eval_expr(expr.rhs)
    elif isinstance(expr, bil.OR):
      return eval_expr(expr.lhs) | eval_expr(expr.rhs)
    elif isinstance(expr, bil.XOR):
      return eval_expr(expr.lhs) ^ eval_expr(expr.rhs)
    elif isinstance(expr, bil.EQ):
      return 1 if eval_expr(expr.lhs) == eval_expr(expr.rhs) else 0
    elif isinstance(expr, bil.NEQ):
      return 1 if eval_expr(expr.lhs) != eval_expr(expr.rhs) else 0
    elif isinstance(expr, bil.LT):
      return 1 if eval_expr(expr.lhs) < eval_expr(expr.rhs) else 0
    elif isinstance(expr, bil.LE):
      return 1 if eval_expr(expr.lhs) <= eval_expr(expr.rhs) else 0
    elif isinstance(expr, bil.SLT): # TODO
      return 1 if eval_expr(expr.lhs) < eval_expr(expr.rhs) else 0
    elif isinstance(expr, bil.SLE): # TODO
      return 1 if eval_expr(expr.lhs) <= eval_expr(expr.rhs) else 0
    elif isinstance(expr, bil.NEG):
      return -eval_expr(expr.arg)
    elif isinstance(expr, bil.NOT):
      return ~eval_expr(expr.arg)
    elif isinstance(expr, bil.HIGH):
      return eval_expr(expr.expr).get_high_bits(expr.size)
    elif isinstance(expr, bil.LOW):
      return eval_expr(expr.expr).get_low_bits(expr.size)
    elif isinstance(expr, bil.Cast):
      return eval_expr(expr.expr)
    elif isinstance(expr, bil.Unknown):
      pass
    elif isinstance(expr, bil.Ite):
      if eval_expr(expr.cond):
        return eval_expr(expr.true)
      else:
        return eval_expr(expr.false)
    elif isinstance(expr, bil.Extract):
      val = eval_expr(expr.expr)
      return val.get_bits(expr.low_bit, expr.high_bit)
    elif isinstance(expr, bil.Concat):
      lhs = eval_expr(expr.lhs)
      rhs = eval_expr(expr.rhs)
      return lhs.concat(rhs)

  return eval_expr(expr)

def run_bil_instruction(st, state):
  """
  Modifies the state based on the statement.
  Returns True if a jump was ran
  """

  hit_jump = False
  if isinstance(st, bil.Move):
    state[st.var.name] = eval_bil_expr(st.expr, state)
  elif isinstance(st, bil.Jmp):
    newpc = eval_bil_expr(st.arg, state)
    state["PC"] = newpc
    hit_jump = True
  elif isinstance(st, bil.If):
    if eval_bil_expr(st.cond, state):
      hit_jump = execute_bil_statements(st.true, state)
    else:
      hit_jump = execute_bil_statements(st.false, state)
  elif isinstance(st, bil.While):
    while (eval_bil_expr(st.cond, state)):
      hit_jump = hit_jump or execute_bil_statements(st.stmts, state)
  return hit_jump

def execute_bil_statements(statements, state):
  """
  Modifies the state based on the statements.
  Returns True if a jump was ran
  """

  hit_jump = False

  if not isinstance(statements, collections.Iterable):
    statements = [statements]

  for st in statements:
    hit_jump = hit_jump or run_bil_instruction(st, state)

  return hit_jump

class Issue:
  def __init__(self, clnum, insn, message):
    self.clnum = clnum
    self.insn = insn
    self.message = message

class Warning(Issue):
  pass

class Error(Issue):
  pass

def validate_bil(program, flow):
  r"""
  Runs the concrete executor, validating the the results are consistent with the trace.
  Returns a tuple of (Errors, Warnings)
  Currently only supports ARM
  """

  trace = program.traces[0]
  libraries = [(m[3],m[1]) for m in trace.mapped]
  registers = program.tregs[0]
  regsize = 8 * program.tregs[1]

  errors = []
  warnings = []

  def new_state_for_clnum(clnum):
    initial_regs = map(lambda x: ConcreteBitVector(regsize, x), trace.db.fetch_registers(clnum))
    initial_vars = dict(zip(registers, initial_regs))
    initial_mem_get = partial(trace.fetch_raw_memory, clnum)
    return State(initial_vars, initial_mem_get)

  state = new_state_for_clnum(0)

  for (addr,data,clnum,ins) in flow:
    instr = program.static[addr]['instruction']
    if not isinstance(instr, BapInsn):
      errors.append(Error(clnum, instr, "Could not make BAP instruction for %s" % str(instr)))
      state = new_state_for_clnum(clnum)
    else:
      bil_instrs = instr.insn.bil
      if bil_instrs is None:
        errors.append(Error(clnum, instr, "No BIL for instruction %s" % str(instr)))
        state = new_state_for_clnum(clnum)
      else:

        # this is bad.. fix this
        oldpc = state["PC"]
        state["PC"] += 8 #Qira PC is wrong
        try:
          jumped = execute_bil_statements(bil_instrs, state)
        except KeyError as e:
          errors.append(Error(clnum, instr, "No BIL variable %s!" % str(e)))

        if not jumped:
          state["PC"] -= 4

        validate = True
        PC = state["PC"]
        if PC > 0xf0000000 or any([PC >= base and PC <= base+size for (base,size) in libraries]):
          # we are jumping into a library that we can't trace.. reset the state and continue
          warnings.append(Warning(clnum, instr, "Jumping into library. Cannot trace this"))
          state = new_state_for_clnum(clnum)
          continue

        error = False
        correct_regs = dict(zip(registers, trace.db.fetch_registers(clnum)))

        for reg, correct in correct_regs.iteritems():
          if state[reg] != correct:
            error = True
            errors.append(Error(clnum, instr, "%s was incorrect! (%x != %x)." % (reg, state[reg] , correct)))
            state[reg] = correct

        for (addr, val) in state.memory.items():
          realval = trace.fetch_raw_memory(clnum, int(addr), 1)
          if val != realval:
            error = True
            errors.append(Error(clnum, instr, "Value at address %x is wrong! (%x != %x)." % (addr, ord(val), ord(realval))))
            state[addr] = realval

  return (errors, warnings)
