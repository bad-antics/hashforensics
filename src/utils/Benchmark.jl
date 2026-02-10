# Hash algorithm benchmarking

function benchmark_algorithms(; iterations::Int=100_000)
    test_input = "NullSec-HashForensics-Benchmark-2026"
    results = Dict{String, Float64}()
    
    # SHA-1
    t = @elapsed for _ in 1:iterations
        sha1(test_input)
    end
    results["SHA-1"] = iterations / t
    
    # SHA-256
    t = @elapsed for _ in 1:iterations
        sha256(test_input)
    end
    results["SHA-256"] = iterations / t
    
    # SHA-512
    t = @elapsed for _ in 1:iterations
        sha512(test_input)
    end
    results["SHA-512"] = iterations / t
    
    println("\n🔑 Hash Algorithm Benchmark (\$iterations iterations)")
    println("─" ^ 45)
    for (algo, speed) in sort(collect(results), by=x->x[2], rev=true)
        rate = @sprintf("%.0f", speed)
        println("  \$algo: \$rate hashes/sec")
    end
    println("─" ^ 45)
    
    return results
end
