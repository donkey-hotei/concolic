#!/usr/bin/python
# -* coding: utf8 *-
import angr
import monkeyhex
from pwn import *


def solve_yellow_wire():
    proj = angr.Project("./bomb")

    start_addr  = 0x08049724  # aprés yellow_preflight
    buffer_addr = 0x0804c24c
    # initializé aprés l'appel de yellow_preflight
    state = proj.factory.blank_state(addr=start_addr)
    # 8 bytes of symbolic input
    unlock_password = state.se.BVS("password", 8 * 8)
    # lier l'entrée symbolique à l'address du tampon
    state.memory.store(buffer_addr, unlock_password)

    simgr = proj.factory.simgr(state)
    # explorer jusqu'a trouver le bloc qui désamorce jaune
    simgr.explore(find=0x0804978b)

    s = simgr.found[0]
    # conreteize l'entrée symbolique à cet état
    password = s.se.eval(unlock_password, cast_to=str)

    return password


def solve_green_wire():
    proj = angr.Project("./bomb", auto_load_libs=False)

    start_addr = 0x08049927  # aprés green_preflight
    # initialize aprés l'appel de green_preflight
    state = proj.factory.blank_state(addr=start_addr)
    # faire 20 octets de l'entrée symbolique
    unlock_password = state.se.BVS("password", 8 * 20)
    # import ipdb; ipdb.set_trace()

    simgr = proj.factory.simgr(state)
    simgr.explore(find=0x08049946, avoid=0x0804998e)

    import ipdb; ipdb.set_trace()

def defuse_bomb():
    io = process("./bomb")
    io.sendline("1")  # jaune

    yellow_wire = solve_yellow_wire()
    io.sendline(yellow_wire)
    print io.recv()

    io.sendline("1")
    green_wire = solve_green_wire()
    io.sendline(green_wire)
    print io.recv()
    # solve_green_wire()
    # solve_red_wire()
    # solve_blue_wire()

if __name__ == "__main__":
    defuse_bomb()

