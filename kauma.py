#!/usr/bin/env python3
#from tasks.parse import ParseJson
from tasks.parser_mp import ParseJson
from argparse import ArgumentParser
from common.common import stderr_write
import multiprocessing as mp

def get_args():
    parser = ArgumentParser()
    parser.add_argument('file', action='store', help='Specify json file')
    return parser.parse_args()
        
def main():
    try:
        args = get_args()
        parser = ParseJson(args.file)
        parser.parse()

    except ValueError as e:
        stderr_write(f"Error: {e}")



if __name__ == "__main__":
    mp.set_start_method('spawn')
    main()
