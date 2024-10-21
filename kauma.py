#!/usr/bin/env python3
from tasks.parse import parse_json
from argparse import ArgumentParser

def get_args():
    parser = ArgumentParser()
    parser.add_argument('file', action='store', help='Specify json file')
    return parser.parse_args()
        
        
def main():
    try:
        args = get_args()
        parser = parse_json(args.file)
        parser.parse()
    except ValueError as e:
        print(f"Error: {e}")



if __name__ == "__main__":
    main()
