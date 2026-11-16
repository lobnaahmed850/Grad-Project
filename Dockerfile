FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
WORKDIR /app
RUN mkdir /state && chown 1000:1000 /state
COPY network-anomaly-detection/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY netguard /app/netguard
COPY logic.py /app/logic.py
COPY network-anomaly-detection/src /app/network-anomaly-detection/src
COPY network-anomaly-detection/models/releases /app/network-anomaly-detection/models/releases
ENV PYTHONPATH=/app:/app/network-anomaly-detection
CMD ["python", "-m", "netguard.service"]
