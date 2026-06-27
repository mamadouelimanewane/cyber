FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn[standard]

COPY src/ ./src/

ENV PYTHONUNBUFFERED=1
ENV COLLECTOR_ID=collector-001
ENV CENTRAL_URL=http://server:8000
ENV SHARED_SECRET=gravity-security-secret-change-me

EXPOSE 8001

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

CMD ["python", "src/main.py", "--port", "8001"]
