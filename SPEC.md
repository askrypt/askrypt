# Askrypt format specification v1.0

This document specifies the JSON text format used by Askrypt for storing password entries. 
The format is designed to be straightforward, human-readable.

## File Structure
An Askrypt file is a JSON with the following fields:
* `version` - version of the Askrypt format (currently "1.0")
* `question0` - first question (string)
* `params` (first-level kdf parameters):
  * `kdf` - key derivation function used (string, default: "pbkdf2")
  * `iterations` - iterations count (integer)
  * `salt` - base64 encoded salt, 16 bytes (string)
* `qs` - base64 encoded encrypted data (string, json), which encrypted by first answer: 
  * `questions` - the rest of the questions
  * `params` (second-level kdf parameters):
    * `kdf` - key derivation function used (string, default: "pbkdf2")
    * `iterations` - iterations count (integer)
    * `salt` - base64 encoded salt, 16 bytes (string)
* `master` - base64 encoded encrypted master key (string, json), which includes:
  * `masterKey` - base64 encoded encrypted master key (string), used to encrypt/decrypt data
  * `iv` - base64 encoded initialization vector (string)
* `data` - base64 encoded encrypted main secret (string, json), which includes a list of user items:
  * `name` - username (string)
  * `secret` - password/secret (string)
  * `url` - url (string)
  * `notes` - notes (string)
  * `type` - type of the entry (string, e.g. "password", "note", etc.)
  * `tags` - list of tags (array of strings)
  * `created` - creation timestamp (string, ISO 8601 format)
  * `modified` - last modified timestamp (string, ISO 8601 format)

```json
{
    "version": "1.0",
    "question0": "What is your mother's maiden name?",
    "params" : {
      "kdf": "pbkdf2",
      "iterations": 600000,
      "salt": "base64-encoded-salt"
    },
    "qs": "base64-encoded-encrypted-questions",
    "master": "base64-encoded-encrypted-master-key",
    "data": "base64-encoded-encrypted-main-secret"
}
```
The question length is **500** UTF-8 characters. Each question is human-readable text. 
The answer is a secret known only to the user. Questions can include spaces and special characters.

Example question:
```
What is your mother's maiden name? (bad question)
What was the name of your first pet? (should be non-common name)
What is the name of the street you grew up on?
What book were you reading when you broke your leg? (Original title)
Who taught you to play chess? (First name Last name)
You first kiss (Name)
You first kiss (City)
```

## Algorithm
The answers are not stored in the file. But before encrypting the answers, all answers are normalized by removing all 
whitespace characters (spaces, tabs), all types of dashes and converting all letters to lowercase.
Then salt, masterKey and iv are generated at the beginning. 

The salt and first answer used as input to calc_pbkdf2 (with specified iterations) 
function to derive the encryption key - named **first-key** (32 bytes).
All other questions and second-level KDF parameters (iterations, salt, kdf) are then encrypted by function encrypt_with_aes (AES-256) via first-key and salt (as IV).

All normalized answers (from second to the last), salt and kdf are then used as input to calc_pbkdf2 (with specified iterations) 
function to derive the encryption key - named **second-key** (32 bytes).

The masterKey and iv are then encrypted by function encrypt_with_aes (AES-256) via second-key and salt (as IV).

The main secret data (list of user items) is then encrypted by function encrypt_with_aes (AES-256) via masterKey and iv.

The masterKey is used because it allows changing the answers without re-encrypting all data
(in the future for large encrypted files).
