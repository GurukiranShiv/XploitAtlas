FROM python:3.13-slim
WORKDIR /app
COPY . .
RUN useradd --uid 10001 --create-home mastermonk && mkdir -p /data && chown -R mastermonk:mastermonk /app /data
USER mastermonk
ENV MASTERMONK_HOST=0.0.0.0 MASTERMONK_PORT=8787 MASTERMONK_DATA_DIR=/data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/api/health', timeout=4)" || exit 1
CMD ["python", "start.py"]
