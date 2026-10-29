FROM python:3.13-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY ews_worker.py index.html ./
ENV MAILWATCH_EWS_DIR=/app MAILWATCH_EWS_API_HOST=0.0.0.0
EXPOSE 18661
CMD ["python", "ews_worker.py"]
