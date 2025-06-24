#!/bin/bash
# MCP Servers Startup Script
# Runs all MCP tool servers on the Kali container

set -e

echo "=== Starting MCP Tool Servers ==="

# Set Python path
export PYTHONPATH=/app:$PYTHONPATH

# Start servers in background
echo "Starting Naabu MCP Server on port 8000..."
python3 /app/mcp/servers/naabu_server.py &
NAABU_PID=$!

echo "Starting Curl MCP Server on port 8001..."
python3 /app/mcp/servers/curl_server.py &
CURL_PID=$!

echo "Starting Nuclei MCP Server on port 8002..."
python3 /app/mcp/servers/nuclei_server.py &
NUCLEI_PID=$!

echo "Starting Metasploit MCP Server on port 8003..."
python3 /app/mcp/servers/metasploit_server.py &
MSF_PID=$!

echo "Starting ffuf Web Fuzzing MCP Server on port 8004..."
python3 /app/mcp/servers/ffuf_server.py &
FFUF_PID=$!

# Function to handle shutdown
shutdown() {
    echo "Shutting down MCP servers..."
    kill $NAABU_PID $CURL_PID $NUCLEI_PID $MSF_PID $FFUF_PID 2>/dev/null || true
    exit 0
}

trap shutdown SIGTERM SIGINT

echo "=== All MCP Servers Started ==="
echo "Naabu: http://localhost:8000 (PID: $NAABU_PID)"
echo "Curl: http://localhost:8001 (PID: $CURL_PID)"
echo "Nuclei: http://localhost:8002 (PID: $NUCLEI_PID)"
echo "Metasploit: http://localhost:8003 (PID: $MSF_PID)"
echo "ffuf: http://localhost:8004 (PID: $FFUF_PID)"

# Wait for all servers
wait
