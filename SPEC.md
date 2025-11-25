# Askrypt plain text format specification v1.0

This document specifies the plain text format used by Askrypt for storing password entries. The format is designed to be simple, human-readable.

## File Structure
An Askrypt file is a JSON with the following fields:
* `version` - version of the Askrypt format (currently "1.0")
* `question0` - first question (string)
* `salt` - base64 encoded salt, 16 bytes (string)
* `iterations` - iterations count (integer)
* `kdf` - key derivation function used (string, default: "pbkdf2")
* `meta` - base64 encoded encrypted data (string, json), which encrypted by first answer: 
  * the rest of the questions
  * `iterations` - iterations count (integer)
  * `salt` - base64 encoded salt, 16 bytes (string)
  * `kdf` - key derivation function used (string, default: "pbkdf2")
* `master` - base64 encoded encrypted master key (string, json), which includes:
  * `masterkey` - base64 encoded encrypted master key (string), used to encrypt/decrypt data
  * `iv` - base64 encoded initialization vector (string)
* `data` - base64 encoded encrypted main secret (string, json), which includes a list of items:
  * `name` - username (string)
  * `secret` - password/secret (string)
  * `url` - url (string)
  * `notes` - notes (string)
  * `type` - type of the entry (string, e.g. "password", "note", etc.)
  * `tags` - list of tags (array of strings)

```json
{
    "version": "1.0",
    "question0": "What is your mother's maiden name?",
    "salt": "base64-encoded-salt",
    "iterations": 600000,
    "kdf": "pbkdf2",
    "meta": "base64-encoded-encrypted-meta",
    "master": "base64-encoded-encrypted-master-key",
    "data": "base64-encoded-encrypted-main-secret"
}
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
TODO: this part: Answers are not stored in the file. But before encrypting the answers, all answers are normalized by removing all whitespace characters (spaces, tabs, ...) 
and converting all letters to lowercase. All normalized answers are concatenated in the order of the questions to form a single string.
Then salt is generated (16 bytes). The salt and concatenated answers used as input to calc_pbkdf2 (with specified iterations) function to derive the encryption key - master-key (32 bytes).
User inputs main secret which is encrypted by function encrypt_with_aes (AES-256) via master-key and salt (IV).

TODO: Specify the exact format of the encrypted data (probably JSON with specified fields/types)
