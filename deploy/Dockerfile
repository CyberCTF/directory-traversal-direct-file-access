FROM python:3.11-slim

WORKDIR /build

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copier les requirements et installer les dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application
COPY . .

# Créer le dossier uploads
RUN mkdir -p uploads

# Créer un utilisateur non-root
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /build
USER appuser

# Exposer le port
EXPOSE 5000

# Commande de démarrage
CMD ["python", "app.py"]
