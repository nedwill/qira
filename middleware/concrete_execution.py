#!/usr/bin/env python2.7

from bap import bil
from functools import partial
from model import BapInsn
import collections

class Memory:
  def __init__(self, fetch_mem, initial=None):
    self.fetch_mem = fetch_mem
    self.memory = {} if initial is None else initial

  def get_mem(self, addr, size, little_endian=True):
    result = "".join([self[address] for address in range(addr, addr+size)])
    if little_endian: result = result[::-1]
    return result

  def set_mem(self, addr, size, val, little_endian=True):
    for i in range(size):
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

def to_val(n, size=None):
  if size is None:
    if n.bit_length() > 33:
      size = 64
    else:
      size = 32

  if n < 0:
    n = (1 << size) + n
  return int(n & ((1 << size) - 1))

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
      return long(mem.encode('hex'), 16)
    elif isinstance(expr, bil.Store):
      addr = eval_expr(expr.idx)
      val = eval_expr(expr.value)
      size = expr.size
      state.set_mem(addr, size / 8, val, isinstance(expr.endian, bil.LittleEndian))
    elif isinstance(expr, bil.Var):
      return state[expr.name]
    elif isinstance(expr, bil.Int):
      return to_val(expr.value, size=expr.size)
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
      return to_val(eval_expr(expr.lhs) + eval_expr(expr.rhs))
    elif isinstance(expr, bil.MINUS):
      return to_val(eval_expr(expr.lhs) - eval_expr(expr.rhs))
    elif isinstance(expr, bil.TIMES):
      return to_val(eval_expr(expr.lhs) * eval_expr(expr.rhs))
    elif isinstance(expr, bil.DIVIDE):
      return to_val(eval_expr(expr.lhs) / eval_expr(expr.rhs))
    elif isinstance(expr, bil.SDIVIDE): # TODO
      return to_val(eval_expr(expr.lhs) / eval_expr(expr.rhs))
    elif isinstance(expr, bil.MOD):
      return to_val(eval_expr(expr.lhs) % eval_expr(expr.rhs))
    elif isinstance(expr, bil.SMOD): # TODO
      return to_val(eval_expr(expr.lhs) + eval_expr(expr.rhs))
    elif isinstance(expr, bil.LSHIFT):
      return to_val(eval_expr(expr.lhs) << eval_expr(expr.rhs))
    elif isinstance(expr, bil.RSHIFT):
      # logical right shift
      # TODO: refactor
      shift = eval_expr(expr.rhs)
      var = eval_expr(expr.lhs)
      if shift >= 1:
        var >>= 1
        var = var & 0x7fffffff
        var >>= (shift - 1)
      return to_val(var)
    elif isinstance(expr, bil.ARSHIFT):
      return to_val(eval_expr(expr.lhs) >> eval_expr(expr.rhs))
    elif isinstance(expr, bil.AND):
      return to_val(eval_expr(expr.lhs) & eval_expr(expr.rhs))
    elif isinstance(expr, bil.OR):
      return to_val(eval_expr(expr.lhs) | eval_expr(expr.rhs))
    elif isinstance(expr, bil.XOR):
      return to_val(eval_expr(expr.lhs) ^ eval_expr(expr.rhs))
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
      mask = (1 << expr.size) - 1
      shift = 32 - expr.size
      return (eval_expr(expr.expr) >> shift) & mask
    elif isinstance(expr, bil.LOW):
      mask = (1 << expr.size) - 1
      return eval_expr(expr.expr) & mask
    elif isinstance(expr, bil.Cast):
      return eval_expr(expr.expr)
    elif isinstance(expr, bil.Unknown):
      pass
    elif isinstance(expr, bil.Ite):
      if eval_bil_expr(expr.cond):
        return eval_expr(expr.true)
      else:
        return eval_expr(expr.false)
    elif isinstance(expr, bil.Extract):
      assert False, "Extract not yet implemented"
      pass
    elif isinstance(expr, bil.Concat):
      assert False, "Concat not yet implemented"
      pass

  return eval_expr(expr)

def run_bil_instruction(st, state):
  if isinstance(st, bil.Move):
    state[st.var.name] = eval_bil_expr(st.expr, state)
  elif isinstance(st, bil.Jmp):
    newpc = eval_bil_expr(st.arg, state)
    state["PC"] = newpc
  elif isinstance(st, bil.If):
    if eval_bil_expr(st.cond, state):
      execute_bil_statements(st.true, state)
    else:
      execute_bil_statements(st.false, state)
  elif isinstance(st, bil.While):
    while (eval_bil_expr(st.cond, state)):
      execute_bil_statements(st.stmts, state)

def execute_bil_statements(statements, state):
  """ Modifies the state based on the statements """

  if not isinstance(statements, collections.Iterable):
    statements = [statements]

  for st in statements:
    run_bil_instruction(st, state)

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
  """

  trace = program.traces[0]
  libraries = [(m[3],m[1]) for m in trace.mapped]
  registers = program.tregs[0]

  errors = []
  warnings = []

  def new_state_for_clnum(clnum):
    initial_regs = trace.db.fetch_registers(clnum)
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
          execute_bil_statements(bil_instrs, state)
        except KeyError as e:
          errors.append(Error(clnum, instr, "No BIL variable %s!" % str(e)))

        if state["PC"] == oldpc + 8:
          state["PC"] -= 4

        validate = True
        PC = state["PC"]
        if PC > 0xf0000000 or True in [PC >= base and PC <= base+size for (base,size) in libraries]:
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
          realval = trace.fetch_raw_memory(clnum, addr, 1)
          if val != realval:
            error = True
            errors.append(Error(clnum, instr, "Value at address %x is wrong! (%x != %x)." % (addr, ord(val), ord(realval))))
            state[addr] = realval

  return (errors, warnings)
