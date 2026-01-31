# HashForensics.jl 🔍

A comprehensive hash forensics toolkit for Julia - identify hash types, analyze patterns, and perform security testing with dictionary and brute-force attacks.

[![Julia](https://img.shields.io/badge/Julia-1.6+-blue.svg)](https://julialang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔎 **Hash Identification** - Auto-detect 40+ hash algorithms
- 📊 **Hash Analysis** - Entropy calculation, pattern detection
- 📖 **Dictionary Attacks** - Wordlist-based cracking with mutations
- 💪 **Brute-Force Attacks** - Customizable charset and length
- 🔄 **Rule Engine** - Leetspeak, case mutations, suffix/prefix rules
- ⚡ **Batch Processing** - Crack multiple hashes efficiently

## Installation

```julia
using Pkg
Pkg.add(url="https://github.com/bad-antics/hashforensics")
```

## Quick Start

### Identify Hash Type

```julia
using HashForensics

# Auto-detect hash type
matches = identify_hash("5d41402abc4b2a76b9719d911017c592")
for m in matches
    println("$(m.name): $(m.description)")
end
# Output: MD5: Message Digest 5 - widely used but cryptographically broken

# Analyze hash in detail
analysis = analyze_hash("5d41402abc4b2a76b9719d911017c592")
println(analysis["possible_types"])  # ["MD5", "NTLM"]
println(analysis["entropy"])         # 3.875
```

### Crack Hashes

```julia
# Dictionary attack
result = crack_hash("5d41402abc4b2a76b9719d911017c592", 
                    method=:dictionary,
                    verbose=true)
println(result.found ? "Cracked: $(result.plaintext)" : "Not found")

# Brute-force attack
result = bruteforce_attack("098f6bcd4621d373cade4e832627b4f6",
                          charset="abcdefghijklmnopqrstuvwxyz",
                          max_len=4,
                          algorithm=MD5)
# Cracked: "test"

# With mutation rules
wordlist = ["password", "admin", "root"]
result = dictionary_attack(target_hash, wordlist, rules=MUTATION_RULES)
```

### Generate Wordlists

```julia
# Generate expanded wordlist with mutations
wordlist = generate_wordlist(
    base_words=["password", "secret"],
    add_numbers=true,     # password1, password123
    add_years=true,       # password2024
    add_special=true,     # password!, password@#
    leetspeak=true        # p455w0rd
)
println(length(wordlist))  # ~500 variations
```

### Batch Processing

```julia
# Crack multiple hashes efficiently
hashes = [
    "5d41402abc4b2a76b9719d911017c592",  # hello
    "098f6bcd4621d373cade4e832627b4f6",  # test
    "e99a18c428cb38d5f260853678922e03",  # abc123
]

results = crack_batch(hashes, verbose=true)
for r in results
    println(format_result(r))
end
```

## Supported Hash Types

| Category | Algorithms |
|----------|------------|
| **MD Family** | MD4, MD5, MD2 |
| **SHA Family** | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512 |
| **Windows** | NTLM, LM |
| **Database** | MySQL 3.23, MySQL 4.1+, Oracle 11g, MSSQL 2012, PostgreSQL MD5 |
| **Web Apps** | WordPress, Drupal 7, Joomla, Django |
| **Network** | Cisco IOS/ASA, Juniper |
| **Modern** | bcrypt, Argon2, scrypt, PBKDF2-SHA256 |
| **Other** | RIPEMD-160, Whirlpool, BLAKE2, Keccak, Tiger |

## API Reference

### Identification

| Function | Description |
|----------|-------------|
| `identify_hash(hash)` | Identify possible hash types |
| `analyze_hash(hash)` | Detailed hash analysis |
| `hash_stats(hashes)` | Statistics for hash collection |

### Cracking

| Function | Description |
|----------|-------------|
| `crack_hash(hash; method, ...)` | Unified cracking interface |
| `dictionary_attack(hash, wordlist)` | Dictionary-based attack |
| `bruteforce_attack(hash; charset, ...)` | Brute-force attack |
| `crack_batch(hashes)` | Efficient batch cracking |

### Wordlists

| Function | Description |
|----------|-------------|
| `generate_wordlist(; kwargs...)` | Generate expanded wordlist |
| `apply_rules(word, rules)` | Apply mutation rules |
| `default_wordlist()` | Common passwords list |

## Security Notice

⚠️ **This tool is for authorized security testing only.**

- Only use against systems you own or have permission to test
- Hash cracking may be illegal without authorization
- Weak algorithms (MD5, SHA-1) should not be used for passwords
- Use bcrypt, Argon2, or scrypt for password hashing

## Use Cases

- 🔬 **Security Research** - Analyze captured hashes
- 🎓 **Education** - Learn about hash algorithms
- 🔐 **Penetration Testing** - Authorized security assessments
- 📊 **Forensics** - Identify unknown hash formats
- ✅ **Password Auditing** - Check password strength

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

Created by [bad-antics](https://github.com/bad-antics)

Part of the [Awesome Julia Security](https://github.com/bad-antics/awesome-julia-security) collection.
