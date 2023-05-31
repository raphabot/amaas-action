import argparse
import time
import json
import os
import hashlib

import amaas.grpc

def scan_file(filePath, handle, hashFile=False):
    s = time.perf_counter()
    result = amaas.grpc.scan_file(filePath, handle)
    elapsed = time.perf_counter() - s
    result = json.loads(result)
    result['scanDuration'] = f"{elapsed:0.2f}s"
    result['filePath'] = filePath
    if hashFile:
        file_hash = hash_file(filePath)
        result['MD5'] = file_hash['MD5']
        result['SHA1'] = file_hash['SHA1']
        result['SHA256'] = file_hash['SHA256']
    return result

def hash_file(filename):
    """"This function returns the SHA-1 hash
    of the file passed into it"""

    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha2 = hashlib.sha256()

    with open(filename, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha2.update(data)

    return {
        "MD5": md5.hexdigest(),
        "SHA1": sha1.hexdigest(),
        "SHA256": sha2.hexdigest()
    }
    
if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--filename', action='store', nargs='*',
                        required=False, help='list of files to be scanned. Defaults to all files in the current directory')
    parser.add_argument('-a', '--addr', action='store', default='127.0.0.1:50051', required=False,
                        help='gRPC server address and port (default 127.0.0.1:50051)')
    parser.add_argument('-r', '--region', action='store',
                        help='AMaaS service region; e.g. us-1 or dev')
    parser.add_argument('--api_key', action='store',
                        help='api key for authentication')
    parser.add_argument('--tls', type=bool, action='store', default=True,
                        help='enable TLS gRPC ')
    parser.add_argument('--ca_cert', action='store', help='CA certificate')
    parser.add_argument('-e', '--exclude', action='store', default='.git/',
                        required=False, help='exclude a file or folder from the scan. Defaults to ".git/"')
    parser.add_argument('--hash', action=argparse.BooleanOptionalAction,
                        required=False, help='generate the hash to be presented in the output')

    args = parser.parse_args()

    if args.region:
        handle = amaas.grpc.init_by_region(args.region, args.api_key, args.tls, args.ca_cert)
    else:
        handle = amaas.grpc.init(args.addr, args.api_key, args.tls, args.ca_cert)  

    total_result = []
    files_to_scan = args.filename
    # If no files are specified, scan all files in the current directory
    if files_to_scan is None:
        files_to_scan = os.listdir(os.getcwd())
    for file in files_to_scan:
        # Checks the file is actually a folder
        if os.path.isdir(file):
            # Get all file paths from the folder
            for root, directories, files in os.walk(file):
                for filename in files:
                    # Join the two strings in order to form the full filepath.
                    filepath = os.path.join(root, filename)
                    # Check if the file is not in the exclude list
                    if args.exclude not in filepath:
                        files_to_scan.append(filepath)
        else:
            total_result.append(scan_file(file, handle, args.hash))

    print(json.dumps(total_result, indent=2))
    amaas.grpc.quit(handle)