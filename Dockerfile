# ⚠️ Intentional IaC issues for the KICS demo: unpinned tag, runs as root, no HEALTHCHECK
FROM python:latest
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app ./app
EXPOSE 5000
CMD ["python", "-m", "app.main"]
