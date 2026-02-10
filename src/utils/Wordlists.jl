# Wordlist management utilities

function download_wordlist(name::String, dest::String)
    wordlists = Dict(
        "rockyou" => "Common password list (14M entries)",
        "common-passwords" => "Top 10K common passwords",
        "english-words" => "English dictionary words",
    )
    
    if !haskey(wordlists, name)
        println("Available wordlists:")
        for (k, v) in wordlists
            println("  \$k: \$v")
        end
        return
    end
    
    mkpath(dirname(dest))
    println("Wordlist '\$name' would be downloaded to: \$dest")
end

function merge_wordlists(files::Vector{String}, output::String; unique::Bool=true)
    words = Set{String}()
    for file in files
        for line in eachline(file)
            push!(words, strip(line))
        end
    end
    
    open(output, "w") do f
        for word in words
            println(f, word)
        end
    end
    println("Merged \$(length(words)) unique words to \$output")
end
