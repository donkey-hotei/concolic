#!/usr/bin/python
import angr
import monkeyhex

if __name__ == "__main__":
    proj = angr.Project("./fauxware")
    state = proj.factory.entry_state()

    while True:
        succ = state.step()
        if len(succ.successors) == 2:
            break
        state = succ.successors[0]

    state1, state2 = succ.successors
    input_data = state1.posix.files[0].all_bytes()
    print state1.solver.eval(input_data, cast_to=str)
    print state2.solver.eval(input_data, cast_to=str)

