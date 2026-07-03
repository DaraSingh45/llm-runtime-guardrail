FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


RUN python -m spacy download en_core_web_sm || echo "spaCy model download failed -- NER layer will be disabled at runtime, DLP regex layer still fully active"

COPY . .


RUN python train/train_classifier.py

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
