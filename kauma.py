#!/usr/bin/env python3
from tasks.parse import parse_json

if __name__ == "__main__":
    parser = parse_json("json.json")  # Replace with your filename
    parser.parse()
