from enum import Enum

debug = False

# -- Memory representation
#    Memory is a sequence of bytes. The address of a byte is its
#    index in that sequence. That's it!
Size = 350
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
def show_memory():
    print("MEMORY:")
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
        show_memory()
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
    if debug:
        print('DEBUG: load_uint8 {} from address {}'.format(val, address))
    return val


# -- Store an unsigned 8-bit int to the given address
def store_uint8(sint, address):
    val = sint % 256
    store_byte(val, address)
    if debug:
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
    if debug:
        print('DEBUG: load_uint16 {} from address {}'.format(val, address))
    return val


# -- Store an unsigned 16-bit int to the given address
def store_uint16(val, address):
    high = (val // 256) % 256
    low = val % 256
    store_byte(high, address)
    store_byte(low, address+1)
    if debug:
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
def mov(src, dest):
    val = get_var(src)
    set_var(dest, val)


# -- Add the value of op1 to op2 and store the result in op2
#    Equivalent to op2 = op1 + op2
#    op1 can be a literal
def add(op1, op2):
    v1 = get_var(op1)
    v2 = get_var(op2)
    v = v1 + v2
    set_var(op2, v)


# -- Subtract op2 from op1, store the result in op1
#    Equivalent to op1 = op1 - op2
#    op2 can be a literal
def sub(op1, op2):
    v1 = get_var(op1)
    v2 = get_var(op2)
    v = v1 - v2
    set_var(op1, v)


# -- Multiply op1 and op2 and store in op3
#    Equivalent to op3 = op1 * op2
#    op1 or op2 can be literals
def mul(op1, op2, op3):
    v1 = get_var(op1)
    v2 = get_var(op2)
    v = v1 * v2
    set_var(op3, v)

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
def load(ptr, typ, op2):
    address = get_var(ptr)
    memvar = (address, typ)
    val = get_var(memvar)
    set_var(op2, val)

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


def make_operand(pc, sp, typ, labels):
    (opstr, pc) = read4(pc)
    if opstr[0] == '#':
        return (int(opstr[1:]), pc)
    elif opstr[0] == '@':
        address = int(opstr[1:])
        return ((address, typ), pc)
    elif opstr.startswith('s+'):
        address = int(opstr[2:]) + sp
        return ((address, typ), pc)
    elif opstr.endswith(':'):
        labelname = opstr.strip(':')
        address = labels[labelname]
        return (address, pc)
    else:
        print("ERROR: malformed operand {}".format(opstr))
        return None


def execute(state, debug):
    (pc, sp, spstack, cflag, labels) = state
    (opcode, pc) = read4(pc)
    if debug:
        print('PC: {:3d}  SP: {:3d}  OP: {}'.format(pc, sp, opcode))
    if opcode == 'noop':
        pass
    elif opcode == 'movb':
        (op1, pc) = make_operand(pc, sp, 'uint8', labels)
        (op2, pc) = make_operand(pc, sp, 'uint8', labels)
        mov(op1, op2)
    elif opcode == 'movw':
        (op1, pc) = make_operand(pc, sp, 'uint16', labels)
        (op2, pc) = make_operand(pc, sp, 'uint16', labels)
        mov(op1, op2)
    elif opcode == 'addb':
        (op1, pc) = make_operand(pc, sp, 'uint8', labels)
        (op2, pc) = make_operand(pc, sp, 'uint8', labels)
        add(op1, op2)
    elif opcode == 'addw':
        (op1, pc) = make_operand(pc, sp, 'uint16', labels)
        (op2, pc) = make_operand(pc, sp, 'uint16', labels)
        add(op1, op2)
    elif opcode == 'subb':
        (op1, pc) = make_operand(pc, sp, 'uint8', labels)
        (op2, pc) = make_operand(pc, sp, 'uint8', labels)
        sub(op1, op2)
    elif opcode == 'subw':
        (op1, pc) = make_operand(pc, sp, 'uint16', labels)
        (op2, pc) = make_operand(pc, sp, 'uint16', labels)
        sub(op1, op2)
    elif opcode == 'jump':
        (op, pc) = make_operand(pc, sp, 'uint16', labels)
        pc = get_var(op)
    elif opcode == 'cmpb':
        (op1, pc) = make_operand(pc, sp, 'uint8', labels)
        (op2, pc) = make_operand(pc, sp, 'uint8', labels)
        v1 = get_var(op1)
        v2 = get_var(op2)
        if v1 == v2:
            cflag = 0
        elif v1 < v2:
            cflag = -1
        else:
            cflag = 1
    elif opcode == 'cmpw':
        (op1, pc) = make_operand(pc, sp, 'uint16', labels)
        (op2, pc) = make_operand(pc, sp, 'uint16', labels)
        v1 = get_var(op1)
        v2 = get_var(op2)
        if v1 == v2:
            cflag = 0
        elif v1 < v2:
            cflag = -1
        else:
            cflag = 1
    elif opcode == 'cmps':
        (op1, pc) = make_operand(pc, sp, 'str', labels)
        (op2, pc) = make_operand(pc, sp, 'str', labels)
        if type(op1) is int:
            memvar1 = (op1, 'str')
        else:
            memvar1 = op1
        v1 = get_var(memvar1)

        if type(op2) is int:
            memvar2 = (op2, 'str')
        else:
            memvar2 = op2
        v2 = get_var(memvar2)

        if v1 == v2:
            cflag = 0
        elif v1 < v2:
            cflag = -1
        else:
            cflag = 1
    elif opcode == 'j_eq':
        (op, pc) = make_operand(pc, sp, 'uint16', labels)
        if cflag == 0:
            pc = get_var(op)
    elif opcode == 'j_lt':
        (op, pc) = make_operand(pc, sp, 'uint16', labels)
        if cflag == -1:
            pc = get_var(op)
    elif opcode == 'j_gt':
        (op, pc) = make_operand(pc, sp, 'uint16', labels)
        if cflag == 1:
            pc = get_var(op)
    elif opcode == 'putb':
        (op, pc) = make_operand(pc, sp, 'uint8', labels)
        v = get_var(op)
        print(v)
    elif opcode == 'putw':
        (op, pc) = make_operand(pc, sp, 'uint16', labels)
        v = get_var(op)
        print(v)
    elif opcode == 'puts':
        (op, pc) = make_operand(pc, sp, 'str', labels)
        if type(op) is int:
            memvar = (op, 'str')
        else:
            memvar = op
        v = get_var(memvar)
        print(v)
    elif opcode == 'gets':
        (op, pc) = make_operand(pc, sp, 'str', labels)
        if type(op) is int:
            memvar = (op, 'str')
        else:
            memvar = op
        v0 = input('?')
        v = do_escapes(v0)
        set_var(memvar, v)
    elif opcode == 'call':
        (op, pc) = make_operand(pc, sp, 'uint16', labels)
        sp = sp - 2
        memvar = (sp, 'uint16')
        set_var(memvar, pc)
        pc = get_var(op)
        spstack.append(sp)
    elif opcode == 'retn':
        sp = spstack.pop(-1)
        memvar = (sp, 'uint16')
        pc = get_var(memvar)
        sp = sp + 2
    elif opcode == 'vars':
        (op, pc) = make_operand(pc, sp, 'uint16', labels)
        val = get_var(op)
        sp = sp - val
    elif opcode == 'exit':
        pc = -1
    else:
        print('ERROR: malformed instruction at PC={} opcode {}'.format(pc, opcode))

    return (pc, sp, spstack, cflag, labels)


def load_program(progstr, debug):
    if debug:
        print("LOAD PROGRAM:")
    address = 10
    start = address
    labelmap = {}
    instructions = progstr.split('\n')
    for ins0 in instructions:
        ins = ins0.strip()
        if ins.startswith('#'):
            pass
        elif len(ins) > 0:
            parts = ins.split(' ', 1)
            if parts[0].endswith(':'):
                labelname = parts[0].strip(':')
                labelmap[labelname] = address
                if debug:
                    print('LABEL {}'.format(labelname))
            elif parts[0].lower() == "data":
                for c in parts[1]:
                    store_byte(ord(c), address)
                    address = address + 1
                store_byte(0, address)
                address = address + 1
            else:
                if len(parts[0]) != 4:
                    print("ERROR in instruction {}".format(ins))
                    exit()
                ins2 = ins.lower()
                if debug:
                    print('{}: {}'.format(address, ins2))
                for c in ins2:
                    if ord(c) > 32:
                        store_byte(ord(c), address)
                        address = address + 1

    if 'start' in labelmap:
        start = labelmap['start']

    return (start, Size, [], 0, labelmap)


def run(program, debug):
    state = load_program(prog, debug)
    if debug:
        show_memory()
    while state[0] > 0:
        state = execute(state, debug)

# === Finally, the program ==========================================

prog = '''
# -- Main function
#    Ask user for name and password, check credentials
start:
vars #010
puts st1:
gets s+00
call fn1:
puts st7:
puts s+00
exit

# -- Check password function
#    Ask for the user's password and check it
fn1:
vars #012
puts st3:
gets s+00
cmps s+00 st2:
j_eq tr1:
puts st6:
jump end:
tr1:
puts st5:
end:
retn

# -- Storage for strings:
st1:
data Enter username:
st2:
data S3cret
st3:
data Enter password:
st4:
data PWNED!
st5:
data Correct
st6:
data Incorrect
st7:
data Done with user:
'''

run(prog, False)
#show_memory()
