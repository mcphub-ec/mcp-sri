FROM python:3.12-slim

WORKDIR /app

# Copy dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Expose the default MCP port; actual port via MCP_PORT at runtime
EXPOSE 8000

# Healthcheck to ensure the container is running and responsive
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import socket, os; s=socket.create_connection(('localhost', int(os.getenv('MCP_PORT', '8000'))), 5); s.close()" || exit 1

# Run the FastMCP server via SSE
CMD ["python", "server.py"]
