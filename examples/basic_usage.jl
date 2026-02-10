# HashForensics - Basic Usage Examples
using HashForensics

# 1. Identify a hash
println("=== Hash Identification ===")
result = identify_hash("5d41402abc4b2a76b9719d911017c592", verbose=true)

# 2. Batch identification
println("\n=== Batch Identification ===")
hashes = [
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
]
results = batch_identify(hashes)
for r in results
    println("\$(r.input[1:16])... => \$(r.algorithms[1].name) (\$(r.algorithms[1].strength))")
end

# 3. Entropy analysis
println("\n=== Entropy Analysis ===")
analysis = entropy_analysis("5d41402abc4b2a76b9719d911017c592")
println("Shannon entropy: \$(analysis["shannon_entropy"])")
println("Assessment: \$(analysis["assessment"])")

# 4. Benchmark
println("\n=== Benchmark ===")
benchmark_algorithms(iterations=10_000)
