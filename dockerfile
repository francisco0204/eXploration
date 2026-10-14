# Imagen base con Node. Le sumamos Python encima porque server.js necesita
# ejecutar main.py como proceso hijo.
FROM node:20-slim

# Python3 + pip + lo mínimo para compilar alguna dependencia nativa si hiciera falta
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# En Debian moderno "python3" no se linkea solo como "python"; lo forzamos
# para no tener que tocar server.js con rutas distintas por plataforma.
RUN ln -s /usr/bin/python3 /usr/bin/python

WORKDIR /app

# ---- Dependencias de Python (requirements.txt vive en la raíz del repo) ----
COPY requirements.txt ./
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# ---- Dependencias de Node (package.json vive en recon-dashboard/backend) ----
COPY recon-dashboard/backend/package*.json recon-dashboard/backend/
RUN cd recon-dashboard/backend && npm install --omit=dev

# ---- Resto del código ----
# (el .dockerignore se encarga de no copiar node_modules, frontend, etc.)
COPY . .

WORKDIR /app/recon-dashboard/backend

ENV PYTHON_BIN=python
EXPOSE 3000

CMD ["node", "server.js"]