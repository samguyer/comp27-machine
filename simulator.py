from enum import Enum

# -- Memory representation
#    Memory is a sequence of bytes. The address of a byte is its
#    index in that sequence. That's it!
Size = 32
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
    for i in range(0, len(Memory), 4):
        line = ''
        for j in range(4):
            b = Memory[i + j]
            line = line + as_binary(b) + ' '
        print('{:3d}  {}'.format(i, line))


# === Memory access ================================================

# -- Load a byte from the given address
#    Raise a 'Segmentation fault' error if the address is outside
#    the legal range for the memory
def load_byte(address):
    if address >= Size or address < 0:
        print("Seg fault")
        return None
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
    return val


# -- Store an unsigned 8-bit int to the given address
def store_uint8(sint, address):
    val = sint % 256
    store_byte(val, address)


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
    low = load_byte(address + 1)
    val = high * 256 + low
    return val


# -- Store an unsigned 16-bit int to the given address
def store_uint16(val, address):
    high = (val // 256) % 256
    low = val % 256
    store_byte(high, address)
    store_byte(low, address + 1)


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
    if type(v) is int:
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
        return None


# --- Set the value of a var
#     Store the value into the address according to its type
def set_var(v, val):
    (address, typ) = v
    if typ == 'uint16':
        store_uint16(val, address)
    if typ == 'sint16':
        store_sint16(val, address)
    if typ == 'uint8':
        store_uint8(val, address)
    if typ == 'sint8':
        store_sint8(val, address)


# === Assembly-like functions =======================================

# -- Move (copy) the value from the src variable to the dest
#    variable, converting the representation if necessary.
#    The src can also be a literal number.
def mov(src, dest):
    if type(src) is int:
        val = src
    else:
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


# ===================================================================

class OpCode(Enum):
    LABEL = 1
    STR = 2
    VAR = 3
    MOV = 4
    ADD = 5
    SUB = 6
    MUL = 7
    DIV = 8
    JE = 9
    JNE = 10
    JLT = 11
    JLE = 12
    JGT = 13
    JGE = 14
    READVAL = 15
    READSTR = 16
    SHOW = 17


# -- Parse the assembly
#
def run(program):
    vars = {}
    labels = {}
    instructions = program.split('\n')
    pc = 0
    end = len(instructions)
    while pc < end:
        inst = instructions[pc].strip()
        if inst and not inst.startswith('#'):
            parts = inst.replace(',', ' ').split()
            opcode = parts[0]
            if opcode.endswith(':'):

                labels[labelname] = pc
            elif opcode == 'var':
                if len(parts) == 4:
                    name = parts[1]
                    addr = int(parts[2])
                    size = parts[3]
                    v = (addr, size)
                    vars[name] = v
                else:
                    print('ERROR: Wrong number of operands for var')
            elif opcode == 'mov':
                if len(parts) == 3:
                    op1 = get_operand(parts[1], vars, labels)
                    op2 = get_operand(parts[2], vars, labels)
                    mov(op1, op2)
                else:
                    print('ERROR: Wrong number of operands for mov')
            elif opcode == 'add':
                if len(parts) == 3:
                    op1 = get_operand(parts[1], vars, labels)
                    op2 = get_operand(parts[2], vars, labels)
                    add(op1, op2)
                else:
                    print('ERROR: Wrong number of operands for add')
            elif opcode == 'show':
                if len(parts) == 3:
                    op1 = get_operand(parts[1], vars, labels)
                    op2 = get_operand(parts[2], vars, labels)
                    show(op1, op2)
                else:
                    print('ERROR: Wrong number of operands for show')

        # pc = exec(pc, inst, vars)
        pc = pc + 1


def parse_instruction(line):
    if line.endswith(':'):
        labelname = line.rstrip(':')
        return (OpCode.LABEL, labelname)
    else:
        parts = line.split(' ', 1)
        opname = parts[0].tolower()
        if opname == 'str':
            s = parts[1].strip().strip('"')
            return (OpCode.STR, s)
        else:


def get_operand(part, vars, labels):
    try:
        v = int(part)
        return v
    except ValueError:
        if part in vars:
            return vars[part]
        elif part in labels:
            return labels[part]
        else:
            return part


run('''
start:
var x, 4, uint16
var y, 8, uint8
loop:
mov 0, x
mov 0, y
add x, y
show 'x', x
''')

# === Finally, the program ==========================================

# small_int = var(4, 'sint8')
# big_int = var(8, 'uint16')
# mov(1, small_int)
# mov(1, big_int)
# while equal(small_int, big_int):
#     add(1, small_int)
#     add(1, big_int)
#
# show('Small int is ', small_int)
# show('Big int is ', big_int)
# show_memory()

