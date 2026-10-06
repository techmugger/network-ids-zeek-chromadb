FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8501

# --server.baseUrlPath=dashboard: Streamlit prefixes its own asset and
# websocket requests with /dashboard/ so the nginx reverse proxy (see
# ../nginx/nginx.conf) can serve this container at /dashboard/ on the
# SAME site as the admin console, with no path collisions against the
# admin console's own /static/ route.
# --server.enableCORS=false / --server.enableXsrfProtection=false:
# Streamlit's own recommended settings when it sits behind a reverse
# proxy - otherwise its CSRF/Origin checks reject requests that arrive
# via the proxy's hostname instead of localhost:8501 directly.
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", \
     "--server.baseUrlPath=dashboard", "--server.enableCORS=false", "--server.enableXsrfProtection=false"]
