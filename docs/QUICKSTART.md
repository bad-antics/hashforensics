# HashForensics Quick Start

## Installation

```julia
using Pkg
Pkg.add(url="https://github.com/bad-antics/hashforensics")
```

## Basic Usage

```julia
using HashForensics

# Identify a hash
result = identify_hash("5d41402abc4b2a76b9719d911017c592")
println(result.algorithms)  # => [MD5, NTLM]

# Entropy analysis
analysis = entropy_analysis("your_hash_here")

# Benchmark algorithms
benchmark_algorithms()

# Start API server
start_api_server(port=8088)
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/identify` | POST | Identify hash algorithm |
| `/crack` | POST | Attempt hash cracking |
| `/benchmark` | GET | Run benchmark |
| `/health` | GET | Health check |
