# Output formatting and display utilities

function print_banner()
    println(raw"""
    ╔═══════════════════════════════════════╗
    ║   🔑 HashForensics v2.0.0            ║
    ║   Julia Security Suite - NullSec     ║
    ╚═══════════════════════════════════════╝
    """)
end

function format_result(result::HashResult)
    lines = String[]
    push!(lines, "─" ^ 50)
    push!(lines, "Hash: $(result.input)")
    push!(lines, "Entropy: $(round(result.entropy, digits=2)) bits")
    push!(lines, "Confidence: $(round(result.confidence * 100, digits=1))%")
    push!(lines, "─" ^ 50)
    for algo in result.algorithms
        strength_color = algo.strength == :weak ? "��" :
                        algo.strength == :medium ? "🟡" :
                        algo.strength == :strong ? "🟢" : "🔵"
        push!(lines, "  $strength_color $(algo.name) [$(algo.category)]")
    end
    push!(lines, "─" ^ 50)
    return join(lines, "\n")
end

function format_crack_result(result::CrackResult)
    if result.success
        return """
✅ CRACKED!
  Hash:      $(result.hash)
  Algorithm: $(result.algorithm)
  Plaintext: $(result.plaintext)
  Method:    $(result.method)
  Attempts:  $(result.attempts)
  Time:      $(round(result.duration, digits=2))s
"""
    else
        return """
❌ NOT CRACKED
  Hash:      $(result.hash)
  Attempts:  $(result.attempts)
  Time:      $(round(result.duration, digits=2))s
"""
    end
end
