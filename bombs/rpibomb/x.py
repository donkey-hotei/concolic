#!/usr/bin/python
# -* coding: utf8 *-
import angr
import monkeyhex
from pwn import *


def solve_yellow_wire():
    proj = angr.Project("./bomb")
    start_addr  = 0x08049724  # aprés yellow_preflight
    buffer_addr = 0x0804c24c
    state = proj.factory.blank_state(addr=start_addr)
    unlock_password = state.se.BVS("password", 8 * 8)
    state.memory.store(buffer_addr, unlock_password)
    simgr = proj.factory.simgr(state)
    simgr.explore(find=0x0804978b)
    s = simgr.found[0]
    password = s.se.eval(unlock_password, cast_to=str)
    print "[*] Yellow wire input: %s" % password
    return password


def solve_green_wire():
    proj = angr.Project("./bomb", auto_load_libs=False)
    start_addr      = 0x08049910
    green_wire_addr = 0x804c12c
    state = proj.factory.blank_state(addr=start_addr)

    while True:
        succ = state.step()
        if len(succ.successors) == 2: break
        state = succ.successors[0]

    state1, state2 = succ.successors

    green_wire = state1.se.BVS("green_wire", 1 * 8)
    state1.memory.store(green_wire_addr, green_wire)

    for b in green_wire.chop(1):
        state.add_constraints(b == 0)

    simgr = proj.factory.simgr(state1)
    simgr.explore(find=0x080499ad, avoid=0x08049993)
    password = state1.posix.dumps(0)[:20].replace("\x00", "")
    print "[*] Green wire input: %s" % password
    return password


def solve_blue_wire():
    proj            = angr.Project("./bomb", auto_load_libs=False)
    buffer_addr     = 0x0804c24c
    state           = proj.factory.blank_state(addr=0x080499fc)
    unlock_password = state.se.BVS("password", 8 * 16)
    state.memory.store(buffer_addr, unlock_password)
    simgr = proj.factory.simgr(state)
    simgr.explore(find=(0x8049ad1,), avoid=(0x08049a5e, 0x08049aec))
    s = simgr.found[0]
    password = s.se.eval(unlock_password, cast_to=str).strip("\x00")
    return password


def solve_red_wire():
    proj = angr.Project("./bomb", auto_load_libs=False)
    buffer_addr     = 0x0804c24c
    red_wire_addr   = 0x0804c28
    state           = proj.factory.blank_state(addr=0x0804983c)
    unlock_password = state.se.BVS("password", 8 * 16)
    red_wire        = state.se.BVS("red_wire", 1 * 8)

    for b in red_wire.chop(1):
        state.add_constraints(b != 0)

    state.memory.store(buffer_addr, unlock_password)
    simgr = proj.factory.simgr(state)
    simgr.explore(find=0x080498c0, avoid=0x08049868)
    import ipdb; ipdb.set_trace()
    return password


def defuse_bomb():
    io = process("./bomb")
    io.sendline("1")  # jaune
    yellow_wire = solve_yellow_wire()
    io.sendline(yellow_wire)
    print io.recv()
    io.sendline("")
    io.sendline("2")  # verde
    green_wire = solve_green_wire()
    io.sendline(green_wire)
    print io.recv()
    print io.recv()
    io.sendline("3")
    blue_wire = solve_blue_wire()
    io.sendline(blue_wire)
    print io.recv()
    print io.recv()
    print io.recv()
    io.sendline("4")
    red_wire = solve_red_wire()
    io.sendline(red_wire)
    print io.recv()
    print io.recv()

if __name__ == "__main__":
    defuse_bomb()

