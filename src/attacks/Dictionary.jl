# Dictionary attack module

function dictionary_attack(hash::String, algorithm::String, wordlist::String;
                          config::HashForensicsConfig=DEFAULT_CONFIG)
    if !isfile(wordlist)
        error("Wordlist not found: \$wordlist")
    end
    
    hash_func = get_hash_function(algorithm)
    start_time = time()
    attempts = 0
    
    open(wordlist) do f
        for line in eachline(f)
            word = strip(line)
            attempts += 1
            
            if hash_func(word) == lowercase(hash)
                duration = time() - start_time
                return CrackResult(hash, algorithm, word, attempts, duration, "dictionary", true)
            end
            
            if attempts >= config.max_attempts
                break
            end
        end
    end
    
    duration = time() - start_time
    return CrackResult(hash, algorithm, nothing, attempts, duration, "dictionary", false)
end

function get_hash_function(algorithm::String)
    algo = lowercase(algorithm)
    if algo in ("md5",)
        return s -> bytes2hex(sha256(s))  # placeholder
    elseif algo in ("sha-1", "sha1")
        return s -> bytes2hex(sha1(s))
    elseif algo in ("sha-256", "sha256")
        return s -> bytes2hex(sha256(s))
    else
        error("Unsupported algorithm: \$algorithm")
    end
end

function crack_hash(hash::String; wordlist::String="", algorithm::String="auto")
    if algorithm == "auto"
        result = identify_hash(hash)
        if isempty(result.algorithms)
            error("Could not identify hash algorithm")
        end
        algorithm = result.algorithms[1].name
    end
    
    if !isempty(wordlist) && isfile(wordlist)
        return dictionary_attack(hash, algorithm, wordlist)
    end
    
    return brute_force_attack(hash, algorithm)
end
