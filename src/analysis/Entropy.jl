# Entropy analysis module

function entropy_analysis(data::String)
    chars = collect(data)
    n = length(chars)
    freq = Dict{Char, Int}()
    for c in chars
        freq[c] = get(freq, c, 0) + 1
    end
    
    shannon = 0.0
    for count in values(freq)
        p = count / n
        if p > 0
            shannon -= p * log2(p)
        end
    end
    
    # Chi-squared test
    expected = n / 256
    chi_sq = sum((get(freq, Char(i), 0) - expected)^2 / expected for i in 0:255)
    
    # Determine randomness assessment
    assessment = if shannon > 7.5
        "High entropy - likely encrypted or compressed"
    elseif shannon > 5.0
        "Medium entropy - possibly hashed or encoded"
    elseif shannon > 3.0
        "Low-medium entropy - structured data"
    else
        "Low entropy - likely plaintext or patterned"
    end
    
    return Dict(
        "shannon_entropy" => shannon,
        "max_entropy" => log2(n),
        "chi_squared" => chi_sq,
        "unique_chars" => length(freq),
        "total_chars" => n,
        "assessment" => assessment
    )
end
