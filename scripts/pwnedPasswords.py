#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
#===================================================================================================
# Title:        Pwned Passwords Local Search
# Scope:        check pwned passwords in local DB from https://haveibeenpwned.com/Passwords
#
# Author:       STech
# Created:      24/02/2018
# Modified:     18/05/2018
# Version:      3.1.5.0350
# Python ver.:  3.6.2
# Copyright:    (c) 2018
# License:      <GPL v3>
#
#===================================================================================================

#===================================================================================================
# README
# *CONDITIONS:
# - DB sources :
#     1. prevalence ordered
#     https://downloads.pwnedpasswords.com/passwords/pwned-passwords-2.0.txt.7z.torrent
#     https://downloads.pwnedpasswords.com/passwords/pwned-passwords-2.0.txt.7z
#     pwned-passwords-2.0.txt.7z | version 2 | 22/02/2018 | 8.8 GB | SHA-1: c267424e7d2bb5b10adff4d776fa14b0967bf0cc
#     pwned-passwords-2.0.txt | 29.43 GB | SHA-1: bf8d8e1c532fcab790680ef7302238f968b4a5d4
#     2. HASH ordered
#     https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ordered-2.0.txt.7z.torrent
#     https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ordered-2.0.txt.7z
#     pwned-passwords-ordered-2.0.txt.7z | version 2 | 01/03/2018 | 9.0 GB | SHA-1: 87437926c6293d034a259a2b86a2d077e7fd5a63
#     pwned-passwords-ordered-2.0.txt | 29.43 GB | SHA-1: 511e242cd64174fd78b27a3fce783b95fe80e475
# - the DB must have for each hit number interval all hashes sorted in increasing order!
#   OR all hash to be ordered
# - after unpack the DB archive, DON'T change the name of .txt DB file!
# - passwords are hashed with SHA-1.
# - the password source file provided must be a text file with each password on a separate line.
#===================================================================================================
'''
__author__    = 'STech'
__version__   = '3.1.5.0350'


import sys
import os
import hashlib

## CONSTANTS
DB_fileName_prevalenceOrdered_C: str = 'pwned-passwords-2.0.txt'
DB_fileName_hashOrdered_C:       str = 'pwned-passwords-ordered-2.0.txt'
DB_path_fileName_C: str = 'DB_path.txt'
intervals_dict_fileName_C: str = 'intervals_dict.py'
firstDBLine_prevalenceOrdered_C: str = '7C4A8D09CA3762AF61E59520943DC26494F8941B:20760336'
firstDBLine_hashOrdered_C:       str = '000000005AD76BD555C1D6D771DE417A4B87E4B4:3'
DB_lines_num_C:   int = 501636842
line_bytes_num_C: int = 63         # the downloaded DB text file has Windows new line characters: '\r\n'
passwords_list_separator_C: str = '|__|'


## MAIN PROGRAM PROCEDURE ========================================================================== MAIN()

def main() -> None:
    '''
    MAIN
    :return: None
    '''
    print('\n=============== SEARCH PWNED PASSWORDS LOCAL ==========================\n')
    ## Set the DB path
    (DB_path, DB_order_type) = setValidDB()
    # main loop
    # user choice to exit from DB path input
    if DB_path == 'Q':
        return None
    while True:
        ## Passwords to find
        (hash_dict, output_path, password_padding) = userInput()
        if hash_dict.get('Q', 0) == 'Q':
            return None
        ## Connect to DB
        while True:
            # Result dictionary
            result_dict: {str:int} = {}
            try:
                with open(DB_path, 'rb+') as db_H:
                    # test if first line is identical with first line from original DB
                    test_line: str = db_H.readline().decode()
                    db_H.seek(0)
                    ## FOR HASH ORDERED DB
                    if test_line.strip() == firstDBLine_hashOrdered_C:
                        hash_dict_iter = hash_dict.copy()
                        for hash_pass, password in hash_dict_iter.items():
                            ## SEARCH ENGINE (BISECTION SEARCH)
                            line_start: int = 1
                            line_end:   int = DB_lines_num_C
                            line_interval_size: int = DB_lines_num_C
                            while True:
                                # positioning file cursor at the beginning of middle line
                                line_middle: int = line_interval_size // 2 + line_start
                                db_H.seek((line_middle-1)*line_bytes_num_C, 0)
                                # extract the hashed password
                                hash_from_DB: str = db_H.read(40).decode()     # '40' is the length of SHA-1 string
                                if hash_pass == hash_from_DB:
                                    # extracting the passwords hits
                                    password_hits: str = ''
                                    # move cursor for extracting password hits - jump the colon
                                    db_H.seek(1,1)
                                    char: str = db_H.read(1).decode()
                                    while char not in (' ', '\n'):
                                        password_hits += char
                                        char = db_H.read(1).decode()
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
                    ## FOR PREVALENCE ORDERED DB
                    elif test_line.strip() == firstDBLine_prevalenceOrdered_C:
                        # test for intervals dict file
                        if not os.path.isfile(os.path.join(sys.path[0], intervals_dict_fileName_C)):
                            askUpdateIntervals(DB_path)
                        ## Import password hits intervals dictionary
                        from intervals_dict import intervals_dict
                        ## ITERATE ENGINE
                        for password_hits, (first_line, last_line) in intervals_dict.items():
                            interval_size: int = last_line - first_line + 1
                            hash_dict_iter = hash_dict.copy()
                            for hash_pass, password in hash_dict_iter.items():
                                ## SEARCH ENGINE (BISECTION SEARCH)
                                line_start: int = first_line
                                line_end:   int = last_line
                                line_interval_size: int = interval_size
                                while True:
                                    # positioning file cursor at the beginning of middle line
                                    line_middle: int = line_interval_size // 2 + line_start
                                    db_H.seek((line_middle-1)*line_bytes_num_C, 0)
                                    # extract the hashed password
                                    hash_from_DB: str = db_H.read(40).decode()     # '40' is the length of SHA-1 string
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
                    else:
                        (DB_path, DB_order_type) = setValidDB()
                        if DB_path == 'Q':
                            print('\nAbort by user.')
                            return None
                        continue     # start over
                    # for the remaining passwords not found, set the password hits count to zero in results
                    for hash_pass, password in hash_dict.items():
                        result_dict[password] = 0
                    ## PRINT RESULTS
                    print(f'\nRESULTS:')
                    print(f'{"Password":<{password_padding}}   {"Hits":>10}')
                    checked_pass_num: int = 0
                    found_pass_num  : int = 0
                    for password, password_hits in result_dict.items():
                        print(f'{password:<{password_padding}} : {password_hits:>10}')
                        checked_pass_num += 1
                        if password_hits != 0:
                            found_pass_num += 1
                    print(f'\n{checked_pass_num} passwords checked: {found_pass_num if (found_pass_num > 0) else "Zero"} passwords found in DB.')
                    ## SAVE RESULTS
                    if output_path not in {'no_path', 'invalid_path'}:
                        try:
                            with open(output_path, 'w') as output_H:
                                output_H.write('PASSWORD,HITS\n')
                                for password, password_hits in result_dict.items():
                                    output_H.write(f'{password},{password_hits}\n')
                                output_H.write(f'\n{checked_pass_num} passwords checked: {found_pass_num if (found_pass_num > 0) else "Zero"} passwords found in DB.\n')
                            print(f'\nFile {output_path} saved successfully.')
                        except:
                            print(f'\nFile {output_path} could NOT be saved.')
                break
            except:
                (DB_path, DB_order_type) = setValidDB()
                if DB_path == 'Q':
                    print('\nAbort by user.')
                    return None
                continue

## MAIN END ---------------------------------------------------------------------------------------- -----

def extractPathFromInput(uInput: str, access_mode: str = 'r',
                         IO_type: str = 'source==', path_type: str = 'file',
                         file_extensions: set = set()) -> str:
    '''
    Extracts the path (source or output) from user input, defined and found by IO_type string;
    Source or Output can be a directory or a file;
    If path contains spaces than it must be enclosed in double quotes.
    :param uInput: [str] the user input string;
    :param access_mode [str] take the values 'r' for reading access mode OR 'w' for writing access mode (defaults to 'r');
    :param IO_type [str] can take usually values as 'source==' or 'output==', but it can take any value wanted by developer (defaults to 'source==');
    :param path_type [str] can take value 'file' OR 'dir'; represents the path type (file or directory) of IO path given (defaults to 'file');
    :param file_extensions [set of str] if is given, is a set of file extensions to check against the IO path given; it is used only if 'path_file' == 'file'; (defaults to empty set); e.g.: {'.csv', '.txt'}
    :return: [str] the normalized and verified path,
                   OR 'no_path' if IO_type wasn't found in input,
                   OR 'invalid_path' if IO_type was found in input but the path wasn't validated
    '''
    # sanitize access mode
    if (access_mode not in {'r', 'w'}):
        access_mode: str = 'r'
    # sanitize path type
    if path_type not in {'file', 'dir'}:
        path_type: str = 'file'
    # path w/ spaces enclosed in double quotes
    if IO_type + '"' in uInput:
        start_path_idx: int = uInput[uInput.find(IO_type + '"') + len(IO_type) + 1:]
        end_path_idx: int = uInput[start_path_idx:].find('"') + start_path_idx
        path: str = os.path.normpath(uInput[start_path_idx:end_path_idx])
    # path w/o spaces
    elif IO_type in uInput:
        path: str = os.path.normpath(uInput[uInput.find(IO_type) + len(IO_type):].split(maxsplit=1)[0])
    # no path
    else:
        return 'no_path'
    # check reading path
    if access_mode == 'r':
        if path_type == 'file' and os.path.isfile(path):
            # if set with file extensions is not empty
            if file_extensions:
                for extension in file_extensions:
                    if path[-len(extension):].lower() == str(extension).lower():
                        return path
                else:
                    return 'invalid_path'
            # if set with extension is empty, don't check extensions and return path
            else:
                return path
        elif path_type == 'dir' and os.path.isdir(path):
            return path
        else:
            return 'invalid_path'
    # check writing path
    elif access_mode == 'w':
        if path_type == 'file' and os.path.isdir(os.path.dirname(path)):
            # if set with file extensions is not empty
            if file_extensions:
                for extension in file_extensions:
                    if path[-len(extension):].lower() == str(extension).lower():
                        return path
                else:
                    return 'invalid_path'
            # if set with extension is empty, don't check extensions and return path
            else:
                return path
        elif path_type == 'dir' and os.path.isdir(path):
            return path
        else:
            return 'invalid_path'

def eliminatePathsFromInput(uInput: str, paths_dict: {str:str}) -> str:
    '''
    Eliminates the paths from user input and replaces them with spaces.
    Works only for VALID paths found previously.
    :param uInput: [str] the user input text
    :param paths_dict: [dict with str] the sequence of IO type and Path pairs to be extracted from user input
           (e.g. {'source==': 'file_path'} OR {'output==': 'dp'})
    :return: [str] the user input without paths
    '''
    if len(paths_dict):
        for IO_type, path in paths_dict.items():
            uInput = uInput[:uInput.find(path)-len(IO_type)].strip() + ' ' + uInput[uInput.find(path)+len(path):].strip()
    return uInput

def userInput() -> ({str:str}, str, int):
    '''
    Takes passwords from user to be found in DB and creates a dictionary with passwords hashes
    Hash algorithm = SHA1
    :return: [tuple of dict of str:str AND a str AND a int] dictionary with hashed passwords and plain text passwords pairs, AND the output path for results AND the maximum length of a password
    '''
    print('\n----------------------------------------------------------------------------')
    print(f'\nInput passwords (separator: {passwords_list_separator_C} ; for Exit press \'Q\'):\n(usage: pass1{passwords_list_separator_C}pass2{passwords_list_separator_C}... [source==/file/with/passwords [output==/file/with/results]] | Q)')
    uInput: str = input('>> ')
    source_path: str = extractPathFromInput(uInput, access_mode = 'r', IO_type = 'source==')
    output_path: str = extractPathFromInput(uInput, access_mode = 'w', IO_type = 'output==')
    password_padding: int = 9
    if uInput.strip().upper() == 'Q' or not len(uInput):
        print('\nAbort by user.')
        return ({'Q':'Q'}, output_path, 0)
    if source_path not in {'no_path', 'invalid_path'}:
        try:
            with open(source_path, 'r') as source_file_H:
                # make the dictionary with hashed passwords
                passwords_list: [str] = []
                for line in source_file_H:
                    # append line as password
                    if line[-1] == '\n':
                        line = line[:-1]
                    passwords_list.append(line)
                    # calculate length of password and save it as maximum length if it's the case
                    if len(line) > password_padding:
                        password_padding = len(line)
                hash_dict: {str:str} = {hashlib.sha1(elem.encode()).hexdigest().upper():elem for elem in passwords_list}
                return (hash_dict, output_path, password_padding)
        except:
            print('\nSource file path could not be opened. Program will stop')
            return ({'Q':'Q'}, output_path, password_padding)
    else:
        # eliminate source/output paths from user input
        uInput = eliminatePathsFromInput(uInput, paths_dict = {'source==': source_path, 'output==': output_path})
        # make the dictionary with hashed passwords
        passwords_list: [str] = uInput.split(sep=passwords_list_separator_C)
        # calculate length of password and save it as maximum length if it's the case
        for password in passwords_list:
            if len(password) > password_padding:
                password_padding = len(password)
        hash_dict: {str:str} = {hashlib.sha1(elem.encode()).hexdigest().upper():elem for elem in passwords_list}
        return (hash_dict, output_path, password_padding)

def setValidDB() -> (str, str):
    '''
    Sets the DB path
    :return: [tuple of str] valid DB path and the DB order type
    '''

    # vars to return
    DB_path: str = ''
    DB_order_type: str = ''
    # construct paths for testing
    DB_path_filePath: str = os.path.join(sys.path[0], DB_path_fileName_C)
    DB_path_prevalenceOrdered_inWrkDir: str = os.path.join(os.getcwd(), DB_fileName_prevalenceOrdered_C)
    DB_path_hashOrdered_inWrkDir: str = os.path.join(os.getcwd(), DB_fileName_hashOrdered_C)
    # try to set the saved DB path from file
    if os.path.isfile(DB_path_filePath):
        try:
            with open(DB_path_filePath, 'r') as DB_path_file_name_H:
                path_from_DB_path_file: str = os.path.normpath(DB_path_file_name_H.readline().strip())
                # test path from DB_path file
                if os.path.isfile(path_from_DB_path_file):
                    DB_path = path_from_DB_path_file
                    # test if first line is identical with first line from original DB
        except: pass
    # try to set the DB file inside script directory
    elif os.path.isfile(DB_path_hashOrdered_inWrkDir):
        DB_path = DB_path_hashOrdered_inWrkDir
    elif os.path.isfile(DB_path_prevalenceOrdered_inWrkDir):
        DB_path = DB_path_prevalenceOrdered_inWrkDir
    while True:
        # test if the DB path and content are valid and return them if they are
        if DB_path:    # NOT empty string (was found)
            try:
                with open(DB_path, 'rb+') as db_H:
                    test_line: str = db_H.readline().decode().strip()
                    if test_line == firstDBLine_prevalenceOrdered_C:
                        DB_order_type: str = 'prevalence'
                        print(f'DB found : {DB_path}  (Ordered by: {DB_order_type}).')
                        # ask user to keep or change DB
                        print(f'Do you want to continue with this DB? (Y/n) (for Exit press \'Q\')')
                        userChoice: str = input('>> ')
                        # choice for exit
                        if userChoice.strip().lower() == 'q':
                            print('\nAbort by user.')
                            return ('Q', 'Q')
                        # choice to keep the DB
                        elif userChoice.strip().lower() != 'n':
                            return (DB_path, DB_order_type)
                        else:
                            print('DB path reset:')
                            # reset DB path to empty string so in next while loop to jump directly to second if statement with input DB path
                            DB_path = ''
                            DB_order_type = ''
                    elif test_line == firstDBLine_hashOrdered_C:
                        DB_order_type: str = 'hash'
                        print(f'DB found : {DB_path}  (Ordered by: {DB_order_type}).')
                        # ask user to keep or change DB
                        print(f'Do you want to continue with this DB? (Y/n) (for Exit press \'Q\')')
                        userChoice: str = input('>> ')
                        # choice for exit
                        if userChoice.strip().lower() == 'q':
                            print('\nAbort by user.')
                            return ('Q', 'Q')
                        # choice to keep the DB
                        elif userChoice.strip().lower() != 'n':
                            return (DB_path, DB_order_type)
                        else:
                            print('DB path reset:')
                            # reset DB path to empty string so in next while loop to jump directly to second if statement with input DB path
                            DB_path = ''
                            DB_order_type = ''
                    else:
                        # reset DB path to empty string so in next while loop to jump directly to second if statement with input DB path
                        DB_path = ''
            except:
                # reset DB path to empty string so in next while loop to jump directly to second if statement with input DB path
                DB_path = ''
        # if the DB order type has remained an empty string the DB path not exists or is invalid
        if not DB_order_type:
            # ask for DB path from user
            print('DB not found. Please enter the DB path. (for Exit press \'Q\')')
            userPath: str = input('>> ')
            # user choice to exit
            if userPath.strip().upper() == 'Q':
                print('\nAbort by user.')
                return ('Q', 'Q')
            DB_path = os.path.normpath(userPath.strip())
            saveDBPath(DB_path)

def saveDBPath(DB_path: str) -> None:
    '''
    Saves DB path in an external .txt file for reusing
    :param DB_path: [str] current DB path
    :return: None
    '''
    print('Do you want to save the DB path? (Y/n)')
    answer: str = input('>> ')
    if answer.strip().upper() == 'Y':
        with open(os.path.abspath(os.path.join(sys.path[0], DB_path_fileName_C)), 'w') as DB_path_file_H:
            DB_path_file_H.write(DB_path)
        print(f'DB path ({DB_path}) was saved.')
    else:
        print(f'DB in use: {DB_path} was not saved for future use.')

def askUpdateIntervals(DB_path: str) -> None:
    '''
    Updates intervals dict python file if user wants it, or makes it by default if it's missing
    :param [str] the valid path to DB
    :return: None
    '''
    if os.path.isfile(os.path.join(sys.path[0], intervals_dict_fileName_C)):
        print('\nDo you want to update password hits count intervals file? (Y/n)')
        answer: str = input('>> ')
    else:
        answer: str = 'Y'
        print('\nPassword hits count intervals file is missing.')
    if answer.strip().upper() == 'Y':
        print('Making password hits count intervals file...')
        with open(DB_path, 'r') as db_H:
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
        with open(os.path.join(sys.path[0], intervals_dict_fileName_C), 'w') as intervals_dict_H:
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

