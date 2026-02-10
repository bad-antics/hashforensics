# Pattern analysis for hash forensics

function detect_encoding(input::String)
    patterns = Dict(
        "Base64" => r"^[A-Za-z0-9+/]+=*$",
        "Hex" => r"^[0-9a-fA-F]+$",
        "Base32" => r"^[A-Z2-7]+=*$",
        "URL Encoded" => r"(%[0-9A-Fa-f]{2})+",
        "JWT" => r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$",
    )
    
    detected = String[]
    for (name, pattern) in patterns
        if occursin(pattern, input)
            push!(detected, name)
        end
    end
    return detected
end

function find_hash_patterns(text::String)
    results = Dict{String, Vector{String}}()
    
    # Common hash patterns in text
    md5_matches = collect(m.match for m in eachmatch(r"\b[a-f0-9]{32}\b", text))
    sha1_matches = collect(m.match for m in eachmatch(r"\b[a-f0-9]{40}\b", text))
    sha256_matches = collect(m.match for m in eachmatch(r"\b[a-f0-9]{64}\b", text))
    
    !isempty(md5_matches) && (results["MD5/NTLM"] = md5_matches)
    !isempty(sha1_matches) && (results["SHA-1"] = sha1_matches)
    !isempty(sha256_matches) && (results["SHA-256"] = sha256_matches)
    
    return results
end
