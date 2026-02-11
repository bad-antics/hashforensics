# HashForensics Documentation

## Overview

HashForensics is a hash analysis and forensic verification toolkit. It provides tools for hash identification, cracking benchmarks, rainbow table management, and forensic file verification.

## Features

- **Hash Identification** — Auto-detect 50+ hash types
- **Batch Verification** — Verify file integrity at scale
- **Rainbow Tables** — Generate and manage rainbow tables
- **Hash Comparison** — Compare hash sets for forensic analysis
- **Timeline** — Track file hash changes over time
- **NSRL Integration** — Check against NIST NSRL hash database

## Supported Hash Types

| Category | Algorithms |
|----------|-----------|
| Common | MD5, SHA-1, SHA-256, SHA-512 |
| Modern | SHA-3, BLAKE2b, BLAKE3 |
| Password | bcrypt, scrypt, Argon2, PBKDF2 |
| System | NTLM, NTLMv2, LM, MySQL, MSSQL |
| Web | WordPress, Drupal, Django, PHPass |

## Usage

```bash
# Identify a hash
hashforensics identify "5f4dcc3b5aa765d61d8327deb882cf99"
# → MD5 (confidence: 98%)

# Verify directory integrity
hashforensics verify --algorithm sha256 --recursive ./evidence/

# Compare two hash sets
hashforensics compare baseline.txt current.txt --output changes.json
```
