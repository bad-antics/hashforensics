# Rainbow table generation and lookup

function generate_rainbow(algorithm::String, wordlist::String, output::String;
                         chain_length::Int=1000)
    hash_func = get_hash_function(algorithm)
    
    open(output, "w") do out
        open(wordlist) do f
            for line in eachline(f)
                word = strip(line)
                h = hash_func(word)
                println(out, "\$(word)\t\$(h)")
            end
        end
    end
    
    println("Rainbow table generated: \$output")
end

function rainbow_lookup(hash::String, table_path::String)
    target = lowercase(hash)
    
    open(table_path) do f
        for line in eachline(f)
            parts = split(line, '\t')
            if length(parts) == 2 && strip(parts[2]) == target
                return strip(String(parts[1]))
            end
        end
    end
    
    return nothing
end
