module HashForensics

using SHA
using Random
using Dates
using Printf
using Sockets

# Core modules
include("core/Types.jl")
include("core/Config.jl")
include("core/Display.jl")

# Analysis modules
include("analysis/Identifier.jl")
include("analysis/Entropy.jl")
include("analysis/Patterns.jl")

# Attack modules  
include("attacks/Dictionary.jl")
include("attacks/BruteForce.jl")
include("attacks/Rainbow.jl")
include("attacks/Mutator.jl")

# Utility modules
include("utils/Wordlists.jl")
include("utils/Benchmark.jl")
include("utils/Export.jl")

# API
include("api/Server.jl")

# Main exports
export identify_hash, crack_hash, generate_rainbow
export benchmark_algorithms, entropy_analysis
export HashResult, CrackResult, AlgorithmInfo
export start_api_server, mutate_wordlist

end # module
