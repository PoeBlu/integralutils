#!/usr/bin/env python3

import os
import argparse

from integralutils import RegexHelpers

def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument('-f', '--file-path', action='store', dest='file_path',
        required=True, default=None,
        help="Path of file to use for URL extraction.")
        
    args = parser.parse_args()

    with open(args.file_path, "rb") as b:
        urls = RegexHelpers.find_urls(b.read())
        
    for url in urls:
        print(url)
        
if __name__ == "__main__":
    main()