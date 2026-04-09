FROM python:3.12-slim
WORKDIR /app
RUN pip install cyphera==0.0.1a4 -q
COPY run.py .
WORKDIR /vectors
CMD ["python", "/app/run.py"]
