FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
ENV AGENT_ID=agent-001
ENV COLLECTOR_URL=http://collector-lb:8001
ENV SHARED_SECRET=gravity-security-secret-change-me

CMD ["python", "src/main.py", \
     "--agent-id", "${AGENT_ID}", \
     "--collector", "${COLLECTOR_URL}"]
