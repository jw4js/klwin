#!/usr/bin/env python3

import sys

inp = sys.stdin.read()
S_PRE = "resolved "
inp = [x for x in inp.strip().split('\n') if x.startswith(S_PRE)]
print("#include <stdio.h>")
print()
for s in inp:
    s = s[len(S_PRE):]
    i = s.index(' ')
    s = s[:i]
    print("void __attribute__((ms_abi))",s + "()")
    print("{")
    print("\tputs(\"" + s + " called\");")
    print("}")
    print()
