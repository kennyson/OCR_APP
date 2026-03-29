FROM node:20-slim

# Install Tesseract OCR and Python (required by ocrmypdf)
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    python3 \
    python3-pip \
    python3-venv \
    ghostscript \
    unpaper \
    qpdf \
    && rm -rf /var/lib/apt/lists/*

# Install ocrmypdf into a virtual env to avoid system pip restrictions
RUN python3 -m venv /opt/ocrmypdf-env && \
    /opt/ocrmypdf-env/bin/pip install --no-cache-dir ocrmypdf

# Put the venv on PATH so `ocrmypdf` is found by the Node server
ENV PATH="/opt/ocrmypdf-env/bin:$PATH"

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
