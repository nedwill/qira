#!/usr/bin/env python2.7

from bap import bil
from bap import adt
from functools import partial
from model import BapInsn
from bitvector import ConcreteBitVector
import collections

class Memory(dict):
  def __init__(self, fetch_mem, initial=None):
    self.fetch_mem = fetch_mem
    if initial is not None:
      self.update(initial)

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

  def __getitem__(self, addr):
    if addr not in self:
      self[addr] = self.fetch_mem(addr, 1)

    return self.get(addr)


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
    elif isinstance(name, int):
      return self.memory(name)
    elif isinstance(name, ConcreteBitVector):
      return self.memory(int(name))

  def __setitem__(self, name, val):
    if isinstance(name, str):
      self.variables[name] = val
    else:
      self.memory[int(name)] = val

  def __str__(self):
    return str(self.variables)

class VariableException(Exception):
  pass

class MemoryException(Exception):
  pass

class ConcreteExecutor(adt.Visitor):
  def __init__(self, state, pc):
    self.state = state
    self.pc = pc
    self.jumped = False

  def visit_Load(self, op):
    addr = self.run(op.idx)
    mem = self.state.get_mem(addr, op.size / 8, isinstance(op.endian, bil.LittleEndian))
    if len(mem) == 0:
      raise MemoryException(addr)
    return ConcreteBitVector(op.size, int(mem.encode('hex'), 16))

  def visit_Store(self, op):
    addr = self.run(op.idx)
    val = self.run(op.value)
    self.state.set_mem(addr, op.size / 8, val, isinstance(op.endian, bil.LittleEndian))
    return op.mem

  def visit_Var(self, op):
    try:
      return self.state[op.name]
    except KeyError as e:
      raise VariableException(op.name)

  def visit_Int(self, op):
    return ConcreteBitVector(op.size, op.value)

  def visit_Let(self, op):
    tmp = state.get(op.var.name, None)
    state[var.name] = self.run(op.value)
    result = self.run(op.expr)
    if tmp is None:
      state.remove(op.var.name)
    else:
      state[var.name] = tmp
    return result

  def visit_Unkown(self, op):
    return

  def visit_Ite(self, op):
    return self.run(op.true) if self.run(op.cond) else self.run(op.false)

  def visit_Extract(self, op):
    return self.run(op.expr).get_bits(op.low_bit, op.high_bit)

  def visit_Concat(self, op):
    return self.run(op.lhs).concat(self.run(op.rhs))

  def visit_Move(self, op):
    if isinstance(op.var.type, bil.Imm):
      self.state[op.var.name] = ConcreteBitVector(op.var.type.size, int(self.run(op.expr)))
    else:
      self.run(op.expr) # no need to store Mems

  def visit_Jmp(self, op):
    self.jumped = True
    self.state[self.pc] = self.run(op.arg)

  def visit_While(self, op):
    while self.run(op.cond) == 1:
      adt.visit(self, op.stmts)

  def visit_If(self, op):
    if self.run(op.cond) == 1:
      adt.visit(self, op.true)
    else:
      adt.visit(self, op.false)

  def visit_PLUS(self, op):
    return self.run(op.lhs) + self.run(op.rhs)

  def visit_MINUS(self, op):
    return self.run(op.lhs) - self.run(op.rhs)

  def visit_TIMES(self, op):
    return self.run(op.lhs) * self.run(op.rhs)

  def visit_DIVIDE(self, op):
    return self.run(op.lhs) / self.run(op.rhs)

  def visit_SDIVIDE(self, op):
    return self.run(op.lhs) / self.run(op.rhs)

  def visit_MOD(self, op):
    return self.run(op.lhs) % self.run(op.rhs)

  def visit_SMOD(self, op):
    return self.run(op.lhs) % self.run(op.rhs)

  def visit_LSHIFT(self, op):
    return self.run(op.lhs) << self.run(op.rhs)

  def visit_RSHIFT(self, op):
    return self.run(op.lhs).lrshift(self.run(op.rhs))

  def visit_ARSHIFT(self, op):
    return self.run(op.lhs) >> self.run(op.rhs)

  def visit_AND(self, op):
    return self.run(op.lhs) & self.run(op.rhs)

  def visit_OR(self, op):
    return self.run(op.lhs) | self.run(op.rhs)

  def visit_XOR(self, op):
    return self.run(op.lhs) ^ self.run(op.rhs)

  def visit_EQ(self, op):
    return ConcreteBitVector(1, 1 if self.run(op.lhs) == self.run(op.rhs) else 0)

  def visit_NEQ(self, op):
    return ConcreteBitVector(1, 1 if self.run(op.lhs) != self.run(op.rhs) else 0)

  def visit_LT(self, op):
    return ConcreteBitVector(1, 1 if self.run(op.lhs) < self.run(op.rhs) else 0)

  def visit_LE(self, op):
    return ConcreteBitVector(1, 1 if self.run(op.lhs) <= self.run(op.rhs) else 0)

  def visit_SLT(self, op):
    return ConcreteBitVector(1, 1 if self.run(op.lhs) < self.run(op.rhs) else 0)

  def visit_SLE(self, op):
    return ConcreteBitVector(1, 1 if self.run(op.lhs) <= self.run(op.rhs) else 0)

  def visit_NEG(self, op):
    return -self.run(op.arg)

  def visit_NOT(self, op):
    return ~self.run(op.arg)

  def visit_UNSIGNED(self, op):
    return ConcreteBitVector(op.size, int(self.run(op.expr)))

  def visit_SIGNED(self, op):
    return ConcreteBitVector(op.size, int(self.run(op.expr)))

  def visit_HIGH(self, op):
    return self.run(op.expr).get_high_bits(op.size)

  def visit_LOW(self, op):
    return self.run(op.expr).get_low_bits(op.size)

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
        state["PC"] += 8 #Qira PC is wrong
        executor = ConcreteExecutor(state, "PC")

        try:
          adt.visit(executor, bil_instrs)
        except VariableException as e:
          errors.append(Error(clnum, instr, "No BIL variable %s!" % str(e.args[0])))
        except MemoryException as e:
          errors.append(Error(clnum, instr, "Used invalid address %x." % e.args[0]))

        if not executor.jumped:
          state["PC"] -= 4

        validate = True
        PC = state["PC"]
        if PC > 0xf0000000 or any([PC >= base and PC <= base+size for (base,size) in libraries]):
          # we are jumping into a library that we can't trace.. reset the state and continue
          warnings.append(Warning(clnum, instr, "Jumping into library. Cannot trace this"))
          state = new_state_for_clnum(clnum)
          continue

        error = False
        correct_regs = new_state_for_clnum(clnum).variables

        for reg, correct in correct_regs.iteritems():
          if state[reg] != correct:
            error = True
            errors.append(Error(clnum, instr, "%s was incorrect! (%x != %x)." % (reg, state[reg] , correct)))
            state[reg] = correct

        for (addr, val) in state.memory.items():
          realval = trace.fetch_raw_memory(clnum, addr, 1)
          if len(realval) == 0 or len(val) == 0:
            errors.append(Error(clnum, instr, "Used invalid address %x." % addr))
            # this is unfixable, reset state
            state = new_state_for_clnum(clnum)
          elif val != realval:
            error = True
            errors.append(Error(clnum, instr, "Value at address %x is wrong! (%x != %x)." % (addr, ord(val), ord(realval))))
            state[addr] = realval

  return (errors, warnings)
