using Test
using HashForensics

@testset "HashForensics Tests" begin
    @testset "Hash Identification" begin
        # MD5
        result = identify_hash("d41d8cd98f00b204e9800998ecf8427e")
        @test !isempty(result.algorithms)
        @test any(a -> a.name == "MD5", result.algorithms)
        
        # SHA-256
        result = identify_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        @test any(a -> a.name == "SHA-256", result.algorithms)
        
        # SHA-1
        result = identify_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        @test any(a -> a.name == "SHA-1", result.algorithms)
    end
    
    @testset "Entropy Analysis" begin
        result = entropy_analysis("aaaa")
        @test result["shannon_entropy"] == 0.0
        
        result = entropy_analysis("abcdefghij")
        @test result["shannon_entropy"] > 0.0
        @test result["unique_chars"] == 10
    end
    
    @testset "Pattern Detection" begin
        encodings = detect_encoding("SGVsbG8gV29ybGQ=")
        @test "Base64" in encodings
        
        encodings = detect_encoding("48656c6c6f")
        @test "Hex" in encodings
    end
    
    @testset "Hash Patterns" begin
        text = "The MD5 is d41d8cd98f00b204e9800998ecf8427e found in log"
        results = find_hash_patterns(text)
        @test haskey(results, "MD5/NTLM")
    end
end
