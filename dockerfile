FROM python:3.11-slim

# Establece directorio de trabajo
WORKDIR /app

# Instala herramientas del sistema (incluye curl)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        python3-dev \
        redis-tools \
        iputils-ping \
        dnsutils \
        curl && \
    rm -rf /var/lib/apt/lists/*

# Instala dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -r requirements.txt --timeout 1000

# Copia el código fuente
COPY ./app ./app
RUN ls -l /app/app

EXPOSE 8000

# Comando de arranque
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]