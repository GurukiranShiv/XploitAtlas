FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN useradd --uid 10001 --create-home orbit && mkdir -p /app/runtime && chown -R orbit:orbit /app
USER orbit
ENV VULNORBIT_HOST=0.0.0.0 VULNORBIT_DATA_DIR=/app/runtime PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/api/health', timeout=4)" || exit 1
CMD ["python", "start.py"]
