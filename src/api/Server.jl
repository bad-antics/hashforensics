# REST API server for HashForensics

function start_api_server(; port::Int=8088)
    server = listen(port)
    println("🔑 HashForensics API running on http://localhost:\$port")
    println("Endpoints:")
    println("  POST /identify  - Identify hash algorithm")
    println("  POST /crack     - Attempt hash cracking")
    println("  GET  /benchmark - Run algorithm benchmark")
    println("  GET  /health    - Health check")
    
    while true
        sock = accept(server)
        @async handle_api_request(sock)
    end
end

function handle_api_request(sock)
    try
        request = readline(sock)
        parts = split(request)
        method = parts[1]
        path = parts[2]
        
        # Read headers
        headers = Dict{String,String}()
        while true
            line = readline(sock)
            isempty(line) && break
            key, val = split(line, ": ", limit=2)
            headers[key] = val
        end
        
        response = if path == "/health"
            """{"status": "ok", "version": "2.0.0", "engine": "HashForensics"}"""
        elseif path == "/identify" && method == "POST"
            content_length = parse(Int, get(headers, "Content-Length", "0"))
            body = String(read(sock, content_length))
            result = identify_hash(strip(body))
            format_result(result)
        else
            """{"error": "not found"}"""
        end
        
        write(sock, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\$response")
    catch e
        write(sock, "HTTP/1.1 500\r\n\r\n{\"error\": \"\$(string(e))\"}")
    finally
        close(sock)
    end
end
