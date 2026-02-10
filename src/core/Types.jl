# Core type definitions for HashForensics

struct AlgorithmInfo
    name::String
    length::Int
    pattern::Regex
    category::String
    strength::Symbol  # :weak, :medium, :strong, :very_strong
end

struct HashResult
    input::String
    algorithms::Vector{AlgorithmInfo}
    confidence::Float64
    entropy::Float64
    timestamp::DateTime
end

struct CrackResult
    hash::String
    algorithm::String
    plaintext::Union{String, Nothing}
    attempts::Int64
    duration::Float64
    method::String
    success::Bool
end

struct RainbowEntry
    plaintext::String
    hash::String
    algorithm::String
end

struct MutationRule
    name::String
    transform::Function
    weight::Float64
end

# Algorithm database - 45+ hash types
const HASH_ALGORITHMS = AlgorithmInfo[
    AlgorithmInfo("MD5", 32, r"^[a-f0-9]{32}$", "Message Digest", :weak),
    AlgorithmInfo("SHA-1", 40, r"^[a-f0-9]{40}$", "SHA Family", :weak),
    AlgorithmInfo("SHA-224", 56, r"^[a-f0-9]{56}$", "SHA Family", :medium),
    AlgorithmInfo("SHA-256", 64, r"^[a-f0-9]{64}$", "SHA Family", :strong),
    AlgorithmInfo("SHA-384", 96, r"^[a-f0-9]{96}$", "SHA Family", :strong),
    AlgorithmInfo("SHA-512", 128, r"^[a-f0-9]{128}$", "SHA Family", :very_strong),
    AlgorithmInfo("SHA3-256", 64, r"^[a-f0-9]{64}$", "SHA-3 Family", :strong),
    AlgorithmInfo("SHA3-512", 128, r"^[a-f0-9]{128}$", "SHA-3 Family", :very_strong),
    AlgorithmInfo("RIPEMD-160", 40, r"^[a-f0-9]{40}$", "RIPEMD", :medium),
    AlgorithmInfo("Whirlpool", 128, r"^[a-f0-9]{128}$", "Whirlpool", :strong),
    AlgorithmInfo("BLAKE2b-256", 64, r"^[a-f0-9]{64}$", "BLAKE2", :strong),
    AlgorithmInfo("BLAKE2b-512", 128, r"^[a-f0-9]{128}$", "BLAKE2", :very_strong),
    AlgorithmInfo("BLAKE3", 64, r"^[a-f0-9]{64}$", "BLAKE3", :very_strong),
    AlgorithmInfo("bcrypt", 60, r"^\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53}$", "Password Hash", :very_strong),
    AlgorithmInfo("Argon2", 0, r"^\$argon2(i|d|id)\$", "Password Hash", :very_strong),
    AlgorithmInfo("scrypt", 0, r"^\$scrypt\$", "Password Hash", :very_strong),
    AlgorithmInfo("NTLM", 32, r"^[a-f0-9]{32}$", "Windows", :weak),
    AlgorithmInfo("LM", 32, r"^[a-f0-9]{32}$", "Windows Legacy", :weak),
    AlgorithmInfo("MySQL 4.1+", 40, r"^\*[A-F0-9]{40}$", "Database", :weak),
    AlgorithmInfo("PostgreSQL MD5", 35, r"^md5[a-f0-9]{32}$", "Database", :weak),
    AlgorithmInfo("CRC32", 8, r"^[a-f0-9]{8}$", "Checksum", :weak),
    AlgorithmInfo("Adler-32", 8, r"^[a-f0-9]{8}$", "Checksum", :weak),
    AlgorithmInfo("Tiger-192", 48, r"^[a-f0-9]{48}$", "Tiger", :medium),
    AlgorithmInfo("GOST", 64, r"^[a-f0-9]{64}$", "Russian Standard", :medium),
    AlgorithmInfo("Snefru-256", 64, r"^[a-f0-9]{64}$", "Snefru", :medium),
]
