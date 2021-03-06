pwnedPasswordsLocal
===================
#### Search locally the DB downloaded from <https://haveibeenpwned.com/Passwords> for leaked passwords
_CLI script_

--------------------
## DB sources :
by Troy Hunt - <https://haveibeenpwned.com/Passwords>
* <https://downloads.pwnedpasswords.com/passwords/pwned-passwords-2.0.txt.7z.torrent>
* <https://downloads.pwnedpasswords.com/passwords/pwned-passwords-2.0.txt.7z>
* version 2 | 22/02/2018
* pwned-passwords-2.0.txt.7z&nbsp;&nbsp;&nbsp;--&nbsp;&nbsp;&nbsp;8.8 GB:
    * SHA-1: c267424e7d2bb5b10adff4d776fa14b0967bf0cc
* pwned-passwords-2.0.txt&nbsp;&nbsp;&nbsp;--&nbsp;&nbsp;&nbsp;29.4 GB:
    * SHA-1: bf8d8e1c532fcab790680ef7302238f968b4a5d4

&nbsp;
* <https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ordered-2.0.txt.7z.torrent>
* <https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ordered-2.0.txt.7z>
* version 2 | 01/03/2018
* pwned-passwords-ordered-2.0.txt.7z&nbsp;&nbsp;&nbsp;--&nbsp;&nbsp;&nbsp;9.0 GB:
    * SHA-1: 87437926c6293d034a259a2b86a2d077e7fd5a63
* pwned-passwords-ordered-2.0.txt&nbsp;&nbsp;&nbsp;--&nbsp;&nbsp;&nbsp;29.4 GB:
    * SHA-1: 511e242cd64174fd78b27a3fce783b95fe80e475

## Conditions:
* the prevalence ordered DB must have for each hit number interval all hashes sorted in increasing order
* the hash ordered DB must have all hashes sorted in increasing order
* after unpack the DB archive, DON'T change the name of .txt file and do not edit it
* passwords have to be hashed with SHA-1

--------------------
## Usage

### Requirements :
* [Python 3.6](https://www.python.org/) and up
* Windows / Linux / Mac
* the .txt file with hashed passwords from above
### "Setup" :
* copy the main script **pwnedPasswords.py** in a directory of your choice
* optionally (but **_recommended_**), copy the second script **intervals_dict.py** in the same directory as the main script. The main script will run without it, but at first run it will build it and the process will take several minutes, depending on the hardware. If you will copy it, then you can skip updating it when you will be asked at the script first run.
### Run the script in CLI :
* Windows
```
>> python c:\path\to\the\main\script
```
* Linux
```
$ python3 /path/to/the/main/script
```
or
```
$ cd /to/the/main/script/directory/path
$ sudo chmod a+x pwnedPasswords.py
$ ./pwnedPasswords.py
```
### Input passwords to search for :
Can be put one or more passwords when the script will ask for. 

For more passwords, they will be separated with&nbsp;&nbsp;`|__|`&nbsp;&nbsp;(this strange separator was chosen because passwords can contain any characters; if your password contains this strange combination of characters then you must to manually change the separator variable in main script) :
```
pswd1|__|pswd_2|__|pswd 3|__|pswd,4|__|...
```
Another way to input multiple passwords is to save them in a text file with each password on a separate line. When the script will ask for passwords input, type&nbsp;&nbsp;`source==`&nbsp;&nbsp;followed by the path to the text file with passwords (if the path contains spaces, then enclose the path in double quotes):
```
source==/path/to/the/text/file/with/passwords
source=="/path/with spaces to file/with/passwords"
```
### Input directory/file paths :
When the script will ask for a directory/file path, this can be copied directly from the OS and pasted in CLI (without quotes). The script can handle both Windows and POSIX paths.

--------------------
## Misc
### @TODO :
* make Windows .exe executable
### Credits:
* Troy Hunt - <https://haveibeenpwned.com/Passwords>