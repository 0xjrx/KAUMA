#!/usr/bin/env python3
import sys

def stderr_write(stuff: str):
   sys.stderr.write(stuff + '\n')
   sys.stderr.flush()



