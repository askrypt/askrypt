# Arpwd plain text format specification v1.0

This document specifies the plain text format used by Arpwd for storing password entries. The format is designed to be simple, human-readable.

## File Structure
An Arpwd file consists of three main sections:

```
arpwd-v1.0 // this file can be opened by arpwd
---
Question 1
Question 2
...
Question N
---
encrypted data in base64
```
Each question starts on a new line. The maximum line length is **255** characters. 
Each question is human-readable text. 
The answer is a secret known only to the user. Questions can include spaces and special characters.

Example question:
```
What is your mother's maiden name?
What was the name of your first pet?
What is the name of the street you grew up on?
```


## Algorithm
Answers are not stored in the file. But before encrypting the answers, all answers are normalized by removing all whitespace characters (spaces, tabs, ...) 
and converting all letters to lowercase. All normalized answers are concatenated in the order of the questions to form a single string.
Then salt is generated (16 bytes). The salt and concatenated answers used as input to calc_pbkdf2 (with specified iterations) function to derive the encryption key - master-key (32 bytes).
User inputs main secret which is encrypted by function encrypt_with_aes (AES-256) via master-key and salt (IV).

Encrypted main **secret**, **salt** and **iterations count** are stored in the file in base64 format (the third section).

TODO: Specify the exact format of the encrypted data (probably JSON with specified fields/types)
