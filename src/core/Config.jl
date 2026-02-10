# Configuration management

mutable struct HashForensicsConfig
    max_threads::Int
    wordlist_path::String
    rainbow_path::String
    output_format::Symbol  # :text, :json, :csv
    verbose::Bool
    gpu_enabled::Bool
    max_attempts::Int64
    charset::String
end

const DEFAULT_CONFIG = HashForensicsConfig(
    Threads.nthreads(),
    joinpath(homedir(), ".hashforensics", "wordlists"),
    joinpath(homedir(), ".hashforensics", "rainbow"),
    :text,
    false,
    false,
    10_000_000,
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#\$%^&*"
)

function load_config(path::String="")
    if isempty(path)
        return deepcopy(DEFAULT_CONFIG)
    end
    # Load from TOML config file
    cfg = deepcopy(DEFAULT_CONFIG)
    if isfile(path)
        for line in readlines(path)
            key, val = split(strip(line), "=", limit=2)
            key = strip(key)
            val = strip(val)
            if key == "max_threads"
                cfg.max_threads = parse(Int, val)
            elseif key == "verbose"
                cfg.verbose = val == "true"
            end
        end
    end
    return cfg
end
