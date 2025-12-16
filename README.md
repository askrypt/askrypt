<div align="center">

# Askrypt
Password manager without master password
</div>

## Overview
Askrypt is a secure password/secret manager that does not require a master password. Secrets are encrypted by a 
key derived from user-specific data using PBKDF2 with HMAC-SHA256. The user-specific data is a set of
answers to personal questions known only to the user.

## Performance

PBKDF2 is intentionally slow to prevent brute-force and dictionary attacks. The iteration count can be adjusted 
to balance security and performance. Default iteration count in Askrypt is set to 600,000.

Benchmarks on a typical system:
- 100,000 iterations: ~100ms
- 600,000 iterations: ~600ms
- 1,000,000 iterations: ~1000ms

## References
* https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

## License

This project is open source. See LICENSE file for details.
