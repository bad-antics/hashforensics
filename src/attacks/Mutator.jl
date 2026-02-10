# Wordlist mutation engine

const DEFAULT_MUTATIONS = MutationRule[
    MutationRule("uppercase", uppercase, 1.0),
    MutationRule("lowercase", lowercase, 1.0),
    MutationRule("capitalize", s -> uppercase(s[1:1]) * s[2:end], 0.8),
    MutationRule("reverse", reverse, 0.5),
    MutationRule("leet_basic", leet_speak, 0.7),
    MutationRule("append_123", s -> s * "123", 0.9),
    MutationRule("append_!", s -> s * "!", 0.6),
    MutationRule("prepend_1", s -> "1" * s, 0.4),
    MutationRule("double", s -> s * s, 0.3),
]

function leet_speak(s::String)
    replacements = Dict('a'=>'4', 'e'=>'3', 'i'=>'1', 'o'=>'0', 's'=>'5', 't'=>'7')
    return String([get(replacements, c, c) for c in s])
end

function mutate_wordlist(input::String, output::String;
                        rules::Vector{MutationRule}=DEFAULT_MUTATIONS)
    open(output, "w") do out
        open(input) do f
            for line in eachline(f)
                word = strip(line)
                println(out, word)  # Original
                for rule in rules
                    try
                        mutated = rule.transform(word)
                        println(out, mutated)
                    catch
                        continue
                    end
                end
            end
        end
    end
end
