# Hash identification engine

function identify_hash(hash::String; verbose::Bool=false)
    hash = strip(hash)
    matches = AlgorithmInfo[]
    
    for algo in HASH_ALGORITHMS
        if algo.length > 0 && length(hash) == algo.length
            if occursin(algo.pattern, lowercase(hash))
                push!(matches, algo)
            end
        elseif algo.length == 0  # Variable length (bcrypt, argon2, etc)
            if occursin(algo.pattern, hash)
                push!(matches, algo)
            end
        end
    end
    
    # Calculate confidence based on uniqueness
    confidence = isempty(matches) ? 0.0 : 1.0 / length(matches)
    
    # Calculate entropy
    ent = calculate_entropy(hash)
    
    result = HashResult(hash, matches, confidence, ent, now())
    
    if verbose
        println(format_result(result))
    end
    
    return result
end

function batch_identify(hashes::Vector{String})
    return [identify_hash(h) for h in hashes]
end

function identify_file(filepath::String)
    hashes = readlines(filepath)
    return batch_identify(filter(!isempty, hashes))
end

function calculate_entropy(s::String)
    if isempty(s)
        return 0.0
    end
    freq = Dict{Char, Int}()
    for c in s
        freq[c] = get(freq, c, 0) + 1
    end
    n = length(s)
    entropy = 0.0
    for count in values(freq)
        p = count / n
        entropy -= p * log2(p)
    end
    return entropy * length(s)
end
