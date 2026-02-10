# Export results in various formats

function export_json(results::Vector{HashResult}, filepath::String)
    open(filepath, "w") do f
        println(f, "[")
        for (i, r) in enumerate(results)
            algos = [Dict("name" => a.name, "category" => a.category, 
                         "strength" => string(a.strength)) for a in r.algorithms]
            entry = Dict(
                "hash" => r.input,
                "confidence" => r.confidence,
                "entropy" => r.entropy,
                "algorithms" => algos,
                "timestamp" => string(r.timestamp)
            )
            comma = i < length(results) ? "," : ""
            println(f, "  \$(json_encode(entry))\$comma")
        end
        println(f, "]")
    end
end

function export_csv(results::Vector{HashResult}, filepath::String)
    open(filepath, "w") do f
        println(f, "hash,algorithm,category,strength,confidence,entropy")
        for r in results
            for a in r.algorithms
                println(f, "\$(r.input),\$(a.name),\$(a.category),\$(a.strength),\$(r.confidence),\$(r.entropy)")
            end
        end
    end
end

function json_encode(d::Dict)
    pairs = ["\"\$(k)\": \$(json_value(v))" for (k, v) in d]
    return "{" * join(pairs, ", ") * "}"
end

function json_value(v)
    if v isa String
        return "\"\$v\""
    elseif v isa Number
        return string(v)
    elseif v isa Vector
        return "[" * join([json_encode(x) for x in v], ", ") * "]"
    else
        return "\"\$(string(v))\""
    end
end
