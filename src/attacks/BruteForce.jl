# Brute force attack module

function brute_force_attack(hash::String, algorithm::String;
                           charset::String=DEFAULT_CONFIG.charset,
                           max_length::Int=8,
                           config::HashForensicsConfig=DEFAULT_CONFIG)
    hash_func = get_hash_function(algorithm)
    start_time = time()
    attempts = 0
    chars = collect(charset)
    
    for length in 1:max_length
        for combo in Iterators.product(fill(chars, length)...)
            candidate = String(collect(combo))
            attempts += 1
            
            if hash_func(candidate) == lowercase(hash)
                duration = time() - start_time
                return CrackResult(hash, algorithm, candidate, attempts, duration, "brute_force", true)
            end
            
            if attempts >= config.max_attempts
                duration = time() - start_time
                return CrackResult(hash, algorithm, nothing, attempts, duration, "brute_force", false)
            end
        end
    end
    
    duration = time() - start_time
    return CrackResult(hash, algorithm, nothing, attempts, duration, "brute_force", false)
end

function threaded_brute_force(hash::String, algorithm::String;
                             charset::String=DEFAULT_CONFIG.charset,
                             max_length::Int=6)
    hash_func = get_hash_function(algorithm)
    chars = collect(charset)
    found = Threads.Atomic{Bool}(false)
    result_plaintext = Ref{String}("")
    
    Threads.@threads for first_char in chars
        if found[]
            continue
        end
        for length in 1:max_length-1
            if found[]
                break
            end
            for combo in Iterators.product(fill(chars, length)...)
                candidate = string(first_char, String(collect(combo)))
                if hash_func(candidate) == lowercase(hash)
                    found[] = true
                    result_plaintext[] = candidate
                    break
                end
            end
        end
    end
    
    return found[] ? result_plaintext[] : nothing
end
