# HashForensics - Hash Cracking Examples
using HashForensics

# Dictionary attack (requires a wordlist file)
println("=== Dictionary Attack ===")
# result = crack_hash("5d41402abc4b2a76b9719d911017c592", 
#                     wordlist="/path/to/wordlist.txt",
#                     algorithm="MD5")

# Pattern detection in text
println("\n=== Finding Hashes in Text ===")
sample_text = """
Server log entry: auth failed for user admin
Password hash: 5d41402abc4b2a76b9719d911017c592
Session token SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
"""
patterns = find_hash_patterns(sample_text)
for (algo, hashes) in patterns
    println("Found \$(length(hashes)) \$algo hash(es)")
end
