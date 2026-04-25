FROM python:3.12-slim

WORKDIR /app

# Copy dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Expose the default MCP port (SSE)
EXPOSE 8000

# Healthcheck to ensure the container is running and responsive
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000')" || exit 1

# Run the FastMCP server via SSE
CMD ["python", "server.py"]
