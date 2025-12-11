# 1. Image de base sécurisée et légère
FROM python:3.9-slim

# 2. Mise à jour et installation des dépendances système minimales
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 3. Utiliser un répertoire de travail dédié et non sensible
WORKDIR /app

# 4. Copier uniquement les fichiers nécessaires (bonnes pratiques)
COPY ../api/ .

# 5. Installer les dépendances de manière sécurisée
RUN pip install --no-cache-dir flask

# 6. Créer un utilisateur non-root
RUN useradd -m appuser

# 7. Donner les droits nécessaires
RUN chown -R appuser:appuser /app

# 8. Exécuter l'application en tant qu'utilisateur non-root (important)
USER appuser

# 9. Exposer le port
EXPOSE 5000

# 10. Lancer l'application
CMD ["python", "app.py"]
