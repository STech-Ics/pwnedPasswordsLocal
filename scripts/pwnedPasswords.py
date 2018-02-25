#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
#===================================================================================================
# Title:        Pwned Passwords Local Search
# Scope:        check pwned passwords in local DB from https://haveibeenpwned.com/Passwords
#
# Author:       STech
# Created:      24/02/2018
# Modified:     25/02/2018
# Version:      2.1.2.0216
# Python ver.:  3.6.2
# Copyright:    (c) 2018
# License:      <GPL v3>
#
#===================================================================================================

#===================================================================================================
# README
# *CONDITIONS:
# - DB source :
#     https://downloads.pwnedpasswords.com/passwords/pwned-passwords-2.0.txt.7z.torrent
#     https://downloads.pwnedpasswords.com/passwords/pwned-passwords-2.0.txt.7z
#     pwned-passwords-2.0.txt.7z | version 2 | 22/02/2018 | 8.8GB | SHA-1: c267424e7d2bb5b10adff4d776fa14b0967bf0cc
#     pwned-passwords-2.0.txt | SHA-1: BF8D8E1C532FCAB790680EF7302238F968B4A5D4
# - the DB must have for each hit number interval all hashes sorted in increasing order!
# - after unpack the DB archive, DON'T change the name of .txt DB file!
# - passwords are hashed with SHA-1.
# - the password source file provided must be a text file with each password on a separate line.
#===================================================================================================
'''
__author__    = 'STech'
__version__   = '2.1.2.0218'


import sys
import os
import hashlib

## CONSTANTS
DB_file_name_C: str = 'pwned-passwords-2.0.txt'
DB_path_file_name_C: str = 'DB_path.txt'
intervals_dict_file_name_C: str = 'intervals_dict.py'
firstDBLine_C: str = '7C4A8D09CA3762AF61E59520943DC26494F8941B:20760336'
line_bytes_num_C: int = 63
passwords_list_separator_C: str = '|__|'

## GLOBALS
DB_path_G: str = ''


## MAIN PROGRAM PROCEDURE ========================================================================== MAIN()

def main() -> None:

    global DB_path_G
    ## Passwords to find
    hash_dict: {str:str} = inputPasswords()
    if hash_dict.get('Q', 0) == 'Q':
        return None
    ## Result dictionary
    result_dict: {str:int} = {}
    ## Connect to DB
    DB_path_file_name: str = os.path.join(sys.path[0], DB_path_file_name_C)
    DB_path_wrk_dir: str = os.path.join(os.getcwd(), DB_file_name_C)
    # try to connect to saved DB path
    if os.path.isfile(DB_path_file_name):
        with open(DB_path_file_name, 'r') as DB_path_file_name_H:
            DB_path_G = os.path.normpath(DB_path_file_name_H.readline().strip())
            if not os.path.isfile(os.path.join(sys.path[0], intervals_dict_file_name_C)):
                askUpdateIntervals()
    # try to connect to DB file inside script directory
    elif os.path.isfile(DB_path_wrk_dir):
        DB_path_G = DB_path_wrk_dir
        askUpdateIntervals()
    # connect to DB
    while True:
        try:
            with open(DB_path_G, 'rb+') as db_H:
                # test if first line is identical with first line from original DB
                test_line: str = db_H.readline().decode()
                db_H.seek(0)
                if test_line.strip() == firstDBLine_C:
                    ## Import password hits intervals dictionary
                    from intervals_dict import intervals_dict
                    ## ITERATE ENGINE
                    for password_hits, (first_line, last_line) in intervals_dict.items():
                        interval_size: int = last_line - first_line + 1
                        hash_dict_temp = hash_dict.copy()
                        for hash_pass, password in hash_dict_temp.items():
                            ## SEARCH ENGINE (BISECTION SEARCH)
                            line_start: int = first_line
                            line_end:   int = last_line
                            line_interval_size: int = interval_size
                            while True:
                                line_middle: int = line_interval_size // 2 + line_start
                                db_H.seek((line_middle-1)*line_bytes_num_C, 0)
                                hash_from_DB: str = db_H.read(40).decode()
                                if hash_pass == hash_from_DB:
                                    # IF FOUND, save the password in result dict with the password hits count
                                    result_dict[password] = password_hits
                                    hash_dict.pop(hash_pass)
                                    break
                                elif line_interval_size == 1:   # ..AND 'value != values_list[line_middle]' which is implicit from skipping first 'if'
                                    # IF NOT FOUND , break the search
                                    break
                                elif hash_pass < hash_from_DB:
                                    # line_start remains unchanged
                                    line_end = line_middle - 1
                                    line_interval_size = line_end + 1 - line_start
                                else:
                                    line_start = line_middle
                                    # line_end remains unchanged
                                    line_interval_size = line_end + 1 - line_start
                    # for the remaining passwords not found, set the password hits count to zero in results
                    for hash_pass, password in hash_dict.items():
                        result_dict[password] = 0
                    ## PRINT RESULTS
                    print('\nRESULTS (password = hits):')
                    for password, password_hits in result_dict.items():
                        print(f'{password} : {password_hits}')
                else:
                    print('\nDB corrupted. Please choose another DB.')
                    DB_path_G = inputDBPath()
                    if DB_path_G == 'Q':
                        return None
                    saveDBPath(DB_path_G)
                    askUpdateIntervals()
                    continue
            break
        except:
            DB_path_G = inputDBPath()
            if DB_path_G == 'Q':
                return None
            saveDBPath(DB_path_G)
            askUpdateIntervals()
            continue

## MAIN END ---------------------------------------------------------------------------------------- -----

def inputPasswords() -> {str:str}:
    '''
    Takes passwords from user to be found in DB and creates a dictionary with passwords hashes
    Hash algorithm = SHA1
    :return: [dict of str with str] dictionary with hashed passwords - plain text passwords pairs
    '''
    print(f'\nInput passwords (separator: {passwords_list_separator_C} ; for Exit press \'Q\'):\n(usage: pass1{passwords_list_separator_C}pass2{passwords_list_separator_C}... | path==/path/to/file/with/passwords.txt | Q)')
    passwords_string: str = input('>> ')
    if passwords_string.strip().upper() == 'Q' or not len(passwords_string):
        return {'Q':'Q'}
    elif all((passwords_string.strip().startswith('path=='),
              len(passwords_string.strip()) > 6,
              os.path.isfile(os.path.normpath(passwords_string.strip()[6:])))):
        try:
            with open(os.path.normpath(passwords_string.strip()[6:]), 'r') as pass_file_H:
                passwords_list: [str] = []
                for line in pass_file_H:
                    if line[-1] == '\n':
                        line = line[:-1]
                    passwords_list.append(line)
                hash_dict: {str:str} = {hashlib.sha1(elem.encode()).hexdigest().upper():elem for elem in passwords_list}
                return hash_dict
        except:
            return {'Q':'Q'}
    else:
        passwords_list: [str] = passwords_string.split(sep=passwords_list_separator_C)
        hash_dict: {str:str} = {hashlib.sha1(elem.encode()).hexdigest().upper():elem for elem in passwords_list}
        return hash_dict

def inputDBPath() -> str:
    '''
    Takes the file path to DB and tests it
    :return: [string] valid path to DB
    '''
    print('\nDB not found.\nPlease enter the DB path (for Exit press \'Q\').\n(usage: /path/to/DB)')
    while True:
        DB_path: str = input('>> ')
        if DB_path.strip().upper() == 'Q':
            return 'Q'
        else:
            DB_path = os.path.normpath(DB_path.strip())
            if os.path.isfile(DB_path):
                try:
                    with open(DB_path, 'r') as db_H:
                        test_line: str = db_H.readline()
                        if test_line.strip() == firstDBLine_C:
                            return DB_path
                        else:
                            print('Path is not valid. Try again.\n(usage: "/path/to/DB" OR "mp" for my hardcoded path)')
                            continue
                except:
                    print('Path is not valid. Try again.\n(usage: "/path/to/DB" OR "mp" for my hardcoded path)')
                    continue

def saveDBPath(DB_path: str) -> None:
    '''
    Saves DB path in an external .txt file for reusing
    :param DB_path: [str] current DB path
    :return: None
    '''
    print('\nDo you want to save the DB path? (Y/n)')
    answer: str = input('>> ')
    if answer.strip().upper() == 'Y':
        with open(os.path.abspath(os.path.join(sys.path[0], DB_path_file_name_C)), 'w') as DB_path_H:
            DB_path_H.write(DB_path)
        print('DB path saved.')

def askUpdateIntervals() -> None:
    '''
    Updates intervals dict python file if user wants it, or makes it by default if it's missing
    :return: None
    '''
    global DB_path_G
    if os.path.isfile(os.path.join(sys.path[0], intervals_dict_file_name_C)):
        print('\nDo you want to update password hits count intervals file? (Y/n)')
        answer: str = input('>> ')
    else:
        answer: str = 'Y'
        print('\nPassword hits count intervals file is missing.')
    if answer.strip().upper() == 'Y':
        print('Making password hits count intervals file...')
        with open(DB_path_G, 'r') as db_H:
            # password_hits_prev: int = 0  # initialized later
            password_hits_crt: int = 0
            line_idx_prev: int = 0
            line_idx_crt: int = 0
            intervals: {int: int} = {}
            for line in db_H:
                line_idx_crt += 1
                if password_hits_crt == int(line.strip()[41:]):
                    continue
                # when hits count is changing, write the previous closed interval to dictionary
                else:
                    password_hits_prev: int = password_hits_crt
                    intervals[password_hits_prev] = (line_idx_prev, line_idx_crt-1)
                    # prepare for next (current) interval
                    password_hits_crt = int(line.strip()[41:])
                    line_idx_prev = line_idx_crt
            # close and write to dictionary the last interval
            intervals[password_hits_crt] = (line_idx_prev, line_idx_crt)
            # delete first zero pair from dictionary
            intervals.pop(0, (0, 0))
        with open(os.path.join(sys.path[0], intervals_dict_file_name_C), 'w') as intervals_dict_H:
            intervals_dict_H.write("#!/usr/bin/env python3\n__author__ = 'STech'\n\n# dictionary with line numbers intervals of password hit counts from pwned DB\nintervals_dict: {int, (int, int)} = ")
            intervals_dict_H.write(str(intervals))
            intervals_dict_H.write('\n')
        print('Password hits intervals dictionary saved as python file in script directory.')


## RUN
if __name__ == '__main__':
    main()
## EXIT
print('\nProgram terminated.')
input('_')
sys.exit(0)

