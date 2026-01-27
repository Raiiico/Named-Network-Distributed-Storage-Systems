#!/usr/bin/env python3
"""Simple uploader CLI for the Named Networks prototype.
Usage: python upload.py <local_path> <dest_name> [host] [port]
Example: python upload.py C:\temp\file.txt /dlsu/uploads/file.txt 127.0.0.1 9001
"""
import sys
from simple_client import SimpleClient

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python upload.py <local_path> <dest_name> [host] [port] [client_id]")
        sys.exit(1)

    local_path = sys.argv[1]
    dest_name = sys.argv[2]
    host = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 9001
    client_id = sys.argv[5] if len(sys.argv) > 5 else "uploader"

    client = SimpleClient(client_id)
    success = client.upload_file(local_path, dest_name, host, port)
    if success:
        print("Upload finished successfully")
    else:
        print("Upload failed")
