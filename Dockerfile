# ✅ FIXED: pinned slim base, non-root user, HEALTHCHECK
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 appuser
COPY app ./app
USER appuser
ENV APP_HOST=0.0.0.0
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')"
CMD ["python", "-m", "app.main"]
