from enum import Enum

# -- Debugging flags
ShowProgram = False
ShowSteps = False
ShowMemoryOps = False
ShowMemory = True

# -- Memory representation
#    Memory is a sequence of bytes. The address of a byte is its
#    index in that sequence. That's it!
Size = 350
Text = 10
Data = 200
Stack = 350
Memory = [0 for _ in range(Size)]


# -- Clear memory
#    Set all the bits to 0
def clear_memory():
    for i in range(len(Memory)):
        Memory[i] = 0


# -- Convert a byte to a binary string
#    For use in printing the memory state as bits
def as_binary(byte):
    bin = ''
    for bit in range(8):
        if byte & 128 == 0:
            bin = bin + '0'
        else:
            bin = bin + '1'
        byte = byte << 1
    return bin


# -- Show contents of memory
#    Display all the bits in memory. This format prints the
#    bytes in order, with four bytes (32 bits) on each line
#    The column at the left side shows the address.
def show_memory(when):
    print("MEMORY {}:".format(when))
    for i in range(0, len(Memory), 10):
        line = ''
        chars = ''
        for j in range(10):
            b = Memory[i + j]
            line = line + as_binary(b) + ' '
            if b >= 32 and b <= 126:
                chars = chars + chr(b) + ' '
            else:
                chars = chars + '. '
        print('{:3d}  {}  {}'.format(i, line, chars))


# === Memory access ================================================

# -- Load a byte from the given address
#    Raise a 'Segmentation fault' error if the address is outside
#    the legal range for the memory
def load_byte(address):
    if address >= Size or address < 0:
        print("Seg fault: improper access at address {}".format(address))
        show_memory("at error")
        exit()
        #return None
    else:
        return Memory[address]


# -- Store a byte value to the given address
#    Raise a 'Segmentation fault' error if the address is outside
#    the legal range for the memory
def store_byte(byte, address):
    if address >= Size or address < 0:
        print("Seg fault")
        return None
    else:
        Memory[address] = (byte % 256)


# -- Load an unsigned 8-bit int from the given address
def load_uint8(address):
    val = load_byte(address)
    if ShowMemoryOps:
        print('DEBUG: load_uint8 {} from address {}'.format(val, address))
    return val


# -- Store an unsigned 8-bit int to the given address
def store_uint8(sint, address):
    val = sint % 256
    store_byte(val, address)
    if ShowMemoryOps:
        print('DEBUG: store_uint8 {} to address {}'.format(val, address))


# -- Load a signed 8-bit int from the given address
#    Decode from two's-complement representation
def load_sint8(address):
    uint = load_uint8(address)
    if uint > 127:
        sint = uint - 256
    else:
        sint = uint
    return sint


# -- Store a signed 8-bit int to the given address
#    Convert to two's complement representation
def store_sint8(val, address):
    if val < 0:
        uint = val + 256
    else:
        uint = val
    store_uint8(uint, address)


# -- Load an unsigned 16-bit int from the given address
def load_uint16(address):
    high = load_byte(address)
    low = load_byte(address+1)
    val = high * 256 + low
    if ShowMemoryOps:
        print('DEBUG: load_uint16 {} from address {}'.format(val, address))
    return val


# -- Store an unsigned 16-bit int to the given address
def store_uint16(val, address):
    high = (val // 256) % 256
    low = val % 256
    store_byte(high, address)
    store_byte(low, address+1)
    if ShowMemoryOps:
        print('DEBUG: store_uint16 {} to address {}'.format(high * 256 + low, address))


# -- Load a signed 16-bit int from the given address
def load_sint16(address):
    uint = load_uint16(address)
    if uint > 32767:
        sint = uint - 65536
    else:
        sint = uint
    return sint


# -- Store a signed 16-bit int to the given address
def store_sint16(val, address):
    if val < 0:
        uint = val + 65536
    else:
        uint = val
    store_uint16(uint, address)


# === Variable access functions =====================================

# -- Make a new variable
#    record the address and the type, which must be a string
#    that is one of 'uint8', 'sint8', 'uint16', 'sint16'
#    Return the new variable
def var(address, type):
    return (address, type)

# -- Get the value of a var
#    Load the value from the variable's address according to its type
def get_var(v):
    if type(v) is int or type(v) is str:
        return v
    else:
        (address, typ) = v
        if typ == 'uint16':
            return load_uint16(address)
        if typ == 'sint16':
            return load_sint16(address)
        if typ == 'uint8':
            return load_uint8(address)
        if typ == 'sint8':
            return load_sint8(address)
        if typ == 'str':
            out = ''
            done = False
            while not done:
                memvar = (address, 'uint8')
                val = get_var(memvar)
                if val != 0:
                    c = chr(val)
                    out = out + c
                    address = address + 1
                else:
                    done = True
            return out
        return None


# --- Set the value of a var
#     Store the value into the address according to its type
def set_var(v, val):
    (address, typ) = v
    if typ == 'uint16':
        store_uint16(val, address)
    elif typ == 'sint16':
        store_sint16(val, address)
    elif typ == 'uint8':
        store_uint8(val, address)
    elif typ == 'sint8':
        store_sint8(val, address)
    elif typ == 'str':
        for c in val:
            store(ord(c), address, 'uint8')
            address = address + 1
        store(0, address, 'uint8')


# === Assembly-like functions =======================================

# -- Move (copy) the value from the src variable to the dest
#    variable, converting the representation if necessary.
#    The src can also be a literal number.
def mov(dest, src):
    val = get_var(src)
    set_var(dest, val)


# -- Add the value of op1 to op2 and store the result in dest
#    Equivalent to dest = op1 + op2
#    op1 or op2 can be a literal
def add(dest, op1, op2):
    v1 = get_var(op1)
    v2 = get_var(op2)
    v = v1 + v2
    set_var(dest, v)


# -- Subtract op2 from op1 and store the result in dest
#    Equivalent to dest = op1 - op2
#    op1 or op2 can be a literal
def sub(dest, op1, op2):
    v1 = get_var(op1)
    v2 = get_var(op2)
    v = v1 - v2
    set_var(dest, v)


# -- Multiply op1 and op2 and store in dest
#    Equivalent to dest = op1 * op2
#    op1 or op2 can be literals
def mul(dest, op1, op2):
    v1 = get_var(op1)
    v2 = get_var(op2)
    v = v1 * v2
    set_var(dest, v)


# -- Compare two variables, return True if op1 == op2
#    Either op can be a literal
def equal(op1, op2):
    v1 = get_var(op1)
    v2 = get_var(op2)
    return v1 == v2


# -- Compare two variables, return True if op1 < op2
#    Either op can be a literal
def less_than(op1, op2):
    v1 = get_var(op1)
    v2 = get_var(op2)
    return v1 < v2


# -- Compare two variables, return True if op1 <= op2
#    Either op can be a literal
def less_than_or_equal(op1, op2):
    v1 = get_var(op1)
    v2 = get_var(op2)
    return v1 <= v2


# -- Ask the user to enter a value, store the result in op
def read(msg, op):
    v = int(input(msg))
    set_var(op, v)


# -- Print the value of op with a message (a string)
def show(msg, op):
    v = get_var(op)
    fmt = msg + "{}"
    print(fmt.format(v))


# -- Load a value from an address
#    op1 is a variable whose value will be used as an address
#    (often called a "pointer"). This instruction gets the value
#    at that address and stores it in op2
def load(dest, ptr, typ):
    address = get_var(ptr)
    memvar = (address, typ)
    val = get_var(memvar)
    set_var(dest, val)

# -- Store a value to an address
#    op2 is a variable whose value will be used as an address
#    (often called a "pointer"). This instruction takes the
#    value from op1 and stores it at the address in ptr
def store(op1, ptr, typ):
    val = get_var(op1)
    address = get_var(ptr)
    memvar = (address, typ)
    set_var(memvar, val)


def do_escapes(s0):
    s = ''
    i = 0
    while i < len(s0):
        if s0[i] == '\\':
            s = s + chr(int(s0[i+1]))
            i = i + 2
        else:
            s = s + s0[i]
            i = i + 1
    return s


def readstr(msg, op):
    v0 = input(msg)
    v = do_escapes(v0)
    set_var(op, v)

# ===================================================================
#

# Instruction format
#   IIII11112222
# where
#   IIII is the opcode
#   1111 is op 1
#   2222 is op 2
# and operand can be
#   #xxx for literal
#   @xxx for address
#   +xxx for stack offset

def read4(pc):
    s = ''
    for i in range(4):
        s = s + chr(load_byte(pc))
        pc = pc + 1
    return (s, pc)


def make_operand(pc, sp, typ):
    (opstr, pc) = read4(pc)
    if opstr[0] == '#':
        return (int(opstr[1:]), pc)
    elif opstr[0] == '@':
        address = int(opstr[1:])
        return ((address, typ), pc)
    elif opstr.startswith('s+'):
        address = int(opstr[2:]) + sp
        return ((address, typ), pc)
    else:
        print("ERROR: malformed operand {}".format(opstr))
        return None


def execute(state):
    (pc, sp, cflag) = state
    (opcode, pc) = read4(pc)
    if ShowSteps:
        print('PC: {:3d}  SP: {:3d}  OP: {}  cflag: {}'.format(pc, sp, opcode, cflag))
    if opcode == 'noop':
        pass
    elif opcode == 'movb':
        (dest, pc) = make_operand(pc, sp, 'uint8')
        (src, pc) = make_operand(pc, sp, 'uint8')
        mov(dest, src)
    elif opcode == 'movw':
        (dest, pc) = make_operand(pc, sp, 'uint16')
        (src, pc) = make_operand(pc, sp, 'uint16')
        mov(dest, src)
    elif opcode == 'addb':
        (dest, pc) = make_operand(pc, sp, 'uint8')
        (op1, pc) = make_operand(pc, sp, 'uint8')
        (op2, pc) = make_operand(pc, sp, 'uint8')
        add(dest, op1, op2)
    elif opcode == 'addw':
        (dest, pc) = make_operand(pc, sp, 'uint16')
        (op1, pc) = make_operand(pc, sp, 'uint16')
        (op2, pc) = make_operand(pc, sp, 'uint16')
        add(dest, op1, op2)
    elif opcode == 'subb':
        (dest, pc) = make_operand(pc, sp, 'uint8')
        (op1, pc) = make_operand(pc, sp, 'uint8')
        (op2, pc) = make_operand(pc, sp, 'uint8')
        sub(dest, op1, op2)
    elif opcode == 'subw':
        (dest, pc) = make_operand(pc, sp, 'uint16')
        (op1, pc) = make_operand(pc, sp, 'uint16')
        (op2, pc) = make_operand(pc, sp, 'uint16')
        sub(dest, op1, op2)
    elif opcode == 'mulb':
        (dest, pc) = make_operand(pc, sp, 'uint8')
        (op1, pc) = make_operand(pc, sp, 'uint8')
        (op2, pc) = make_operand(pc, sp, 'uint8')
        mul(dest, op1, op2)
    elif opcode == 'mulw':
        (dest, pc) = make_operand(pc, sp, 'uint16')
        (op1, pc) = make_operand(pc, sp, 'uint16')
        (op2, pc) = make_operand(pc, sp, 'uint16')
        mul(dest, op1, op2)
    elif opcode == 'jump':
        (op, pc) = make_operand(pc, sp, 'uint16')
        (pc, _) = op
    elif opcode == 'cmpb':
        (op1, pc) = make_operand(pc, sp, 'uint8')
        (op2, pc) = make_operand(pc, sp, 'uint8')
        v1 = get_var(op1)
        v2 = get_var(op2)
        if v1 == v2:
            cflag = 0
        elif v1 < v2:
            cflag = -1
        else:
            cflag = 1
    elif opcode == 'cmpw':
        (op1, pc) = make_operand(pc, sp, 'uint16')
        (op2, pc) = make_operand(pc, sp, 'uint16')
        v1 = get_var(op1)
        v2 = get_var(op2)
        if v1 == v2:
            cflag = 0
        elif v1 < v2:
            cflag = -1
        else:
            cflag = 1
    elif opcode == 'cmpi':
        (op1, pc) = make_operand(pc, sp, 'sint8')
        (op2, pc) = make_operand(pc, sp, 'sint8')
        v1 = get_var(op1)
        v2 = get_var(op2)
        if v1 == v2:
            cflag = 0
        elif v1 < v2:
            cflag = -1
        else:
            cflag = 1
    elif opcode == 'cmpl':
        (op1, pc) = make_operand(pc, sp, 'sint16')
        (op2, pc) = make_operand(pc, sp, 'sint16')
        v1 = get_var(op1)
        v2 = get_var(op2)
        if v1 == v2:
            cflag = 0
        elif v1 < v2:
            cflag = -1
        else:
            cflag = 1
    elif opcode == 'cmps':
        (op1, pc) = make_operand(pc, sp, 'str')
        (op2, pc) = make_operand(pc, sp, 'str')
        v1 = get_var(op1)
        v2 = get_var(op2)
        if v1 == v2:
            cflag = 0
        elif v1 < v2:
            cflag = -1
        else:
            cflag = 1
    elif opcode == 'j_eq':
        (op, pc) = make_operand(pc, sp, 'uint16')
        if cflag == 0:
            (pc, _) = op
    elif opcode == 'j_ne':
        (op, pc) = make_operand(pc, sp, 'uint16')
        if cflag != 0:
            (pc, _) = op
    elif opcode == 'j_lt':
        (op, pc) = make_operand(pc, sp, 'uint16')
        if cflag == -1:
            (pc, _) = op
    elif opcode == 'j_gt':
        (op, pc) = make_operand(pc, sp, 'uint16')
        if cflag == 1:
            (pc, _) = op
    elif opcode == 'putb':
        (op, pc) = make_operand(pc, sp, 'uint8')
        v = get_var(op)
        print(v)
    elif opcode == 'getb':
        (op, pc) = make_operand(pc, sp, 'uint8')
        v = int(input('?'))
        set_var(op, v)
    elif opcode == 'putw':
        (op, pc) = make_operand(pc, sp, 'uint16')
        v = get_var(op)
        print(v)
    elif opcode == 'getw':
        (op, pc) = make_operand(pc, sp, 'uint16')
        v = int(input('?'))
        set_var(op, v)
    elif opcode == 'puti':
        (op, pc) = make_operand(pc, sp, 'sint8')
        v = get_var(op)
        print(v)
    elif opcode == 'geti':
        (op, pc) = make_operand(pc, sp, 'sint8')
        v = int(input('?'))
        set_var(op, v)
    elif opcode == 'putl':
        (op, pc) = make_operand(pc, sp, 'sint16')
        v = get_var(op)
        print(v)
    elif opcode == 'getl':
        (op, pc) = make_operand(pc, sp, 'sint16')
        v = int(input('?'))
        set_var(op, v)
    elif opcode == 'puts':
        (op, pc) = make_operand(pc, sp, 'str')
        v = get_var(op)
        print(v)
    elif opcode == 'gets':
        (op, pc) = make_operand(pc, sp, 'str')
        v0 = input('?')
        v = do_escapes(v0)
        set_var(op, v)
    elif opcode == 'call':
        (op, pc) = make_operand(pc, sp, 'uint16')
        sp = sp - 2
        memvar = (sp, 'uint16')
        set_var(memvar, pc)
        (pc, _) = op
    elif opcode == 'push':
        (op, pc) = make_operand(pc, sp, 'uint16')
        sp = sp - op
    elif opcode == 'pop ':
        (op, pc) = make_operand(pc, sp, 'uint16')
        sp = sp + op
    elif opcode == 'retn':
        memvar = (sp, 'uint16')
        pc = get_var(memvar)
        sp = sp + 2
    elif opcode == "bash":
        print("admin$")
        pc = -1
    elif opcode == 'exit':
        pc = -1
    else:
        print('ERROR: malformed instruction at PC={} opcode {}'.format(pc, opcode))

    return (pc, sp, cflag)


# -- Load a program
#    Convert from the human-readable form to the in-memory form

def represents_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


def storeN(s, n, address):
    for i in range(n):
        store_byte(ord(s[i]), address)
        address += 1
    return address


def load_program(instructions):
    if ShowProgram:
        print("LOAD PROGRAM:")
    PC = Text
    start = PC
    labelmap = {}
    labeluses = {}
    datamap = {}
    datacounter = 0
    dataaddress = Data
    varmap = {}
    stackoffset = 0
    enteraddress = 0
    #instructions = progstr.split('\n')
    for ins0 in instructions:
        ins = ins0.strip()
        if ins.startswith('#'):
            # -- Comment line
            pass
        elif len(ins) > 0:
            parts = ins.split(' ', 1)
            opcode = parts[0].lower()
            if opcode.endswith(':'):
                # -- Special case for labels (not a real opcode)
                labelname = opcode.strip(':')
                labelmap[labelname] = PC
                if ShowProgram:
                    print('{}: label {}'.format(PC, labelname))
            else:
                # -- Pull out strings and assign them labels
                operands = []
                if len(parts) > 1:
                    operands0 = parts[1]
                    if '"' in operands0:
                        # -- Data literal: find a place for it in the data space
                        q_start = operands0.find('"')
                        q_end = operands0.find('"', q_start + 1)
                        content = operands0[q_start+1:q_end]
                        nm = 'str' + str(datacounter)
                        if ShowProgram:
                            print("Allocate string {} to address {}".format(nm, dataaddress))
                        datamap[nm] = (content, dataaddress)
                        dataaddress += (len(content) + 1)
                        datacounter += 1
                        operands0 = operands0[0:q_start] + nm + operands0[q_end+1:]
                    # -- Process each kind of instruction
                    operands = operands0.split(',')
                if opcode == 'var':
                    # -- Stack variables: assign them an offset into the stack frame
                    nm = operands[0].strip()
                    typ = operands[1].strip()
                    if typ == 'uint8' or typ == 'sint8' or typ == 'char':
                        size = 1
                    else:
                        size = 2
                    if len(operands) == 3:
                        # -- Buffers have a size operand
                        count = int(operands[2])
                        size = size * count
                    varmap[nm] = stackoffset
                    if ShowProgram:
                        print('Var {} at offset SP+{}'.format(nm, stackoffset))
                    stackoffset += size
                elif opcode == "enter":
                    # -- Leave room for the stack space offset. We won't know this
                    #    value until we get to the exit
                    enteraddress = PC+4
                    PC = storeN('push____', 8, PC)
                elif opcode == 'leave':
                    # -- Back patch the stack size to the enter instruction
                    if enteraddress != 0:
                        omem = '#{:03d}'.format(stackoffset)
                        PC = storeN('pop ', 4, PC)
                        PC = storeN(omem, 4, PC)
                        storeN(omem, 4, enteraddress)
                elif opcode == 'return':
                    PC = storeN('retn', 4, PC)
                else:
                    # -- All other instructions
                    #    Translate the operands into real addresses and values
                    if ShowProgram:
                        print("{}: instruction {} {}".format(PC, opcode, operands))
                    PC = storeN(opcode, 4, PC)
                    for o0 in operands:
                        o = o0.strip()
                        if o.startswith('#'):
                            val = int(o.strip('#'))
                            omem = '#{:03d}'.format(val)
                            PC = storeN(omem, 4, PC)
                        elif o.startswith('@'):
                                val = int(o.strip('@'))
                                omem = '@{:03d}'.format(val)
                                PC = storeN(omem, 4, PC)
                        elif o in datamap:
                            (content, address) = datamap[o]
                            omem = '@{:03d}'.format(address)
                            PC = storeN(omem, 4, PC)
                        elif o in varmap:
                            offset = varmap[o]
                            omem = 's+{:02d}'.format(offset)
                            PC = storeN(omem, 4, PC)
                        else:
                            # -- Must be a label
                            if o in labelmap:
                                address = labelmap[o]
                                omem = '@{:03d}'.format(address)
                                PC = storeN(omem, 4, PC)
                            else:
                                labeluses[PC] = o
                                PC += 4

    #print(labeluses)
    for bp in labeluses:
        label = labeluses[bp]
        target = labelmap[label]
        omem = '@{:03d}'.format(target)
        storeN(omem, 4, bp)
        if ShowProgram:
            print("Back patch {} for target {} at address {}".format(label, target, bp))

    for s in datamap:
        (content, address) = datamap[s]
        storeN(content, len(content), address)
        store_byte(0, address+len(content))

    if 'start' in labelmap:
        start = labelmap['start']

    return (start, Size, 0)


def run(fn):
    # -- Read in the program file
    print('Read program file...')
    instructions = []
    with open(fn) as f:
        instructions = [line.rstrip() for line in f]
    print('...Done')

    # -- Compile and store instructions
    print('Assemble program...')
    state = load_program(instructions)
    print('...Done')

    if ShowMemory:
        show_memory("at start")

    # -- Execute instructions until we hit exit
    print('Run program...')
    while state[0] > 0:
        state = execute(state)

    if ShowMemory:
        show_memory("at end")

    print('...Done')



# === Finally, the main program ==========================================

fn = input('Enter file name: ')
run(fn)
