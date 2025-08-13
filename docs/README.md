# Documentation - Path Traversal Bypass

## Vue d'ensemble

Ce laboratoire présente une vulnérabilité de path traversal dans une application web de gestion de fichiers. L'application implémente un filtre de sécurité basique qui peut être contourné.

## Architecture

### Technologies utilisées
- **Backend**: Flask (Python)
- **Frontend**: HTML, TailwindCSS
- **Containerisation**: Docker
- **Tests**: pytest

### Structure de l'application
```
app/
├── app.py              # Application Flask principale
├── templates/          # Templates HTML
├── uploads/           # Fichiers de test
└── requirements.txt   # Dépendances Python
```

## Vulnérabilité

### Description
L'application filtre les séquences `../` dans les noms de fichiers mais ne gère pas l'encodage URL. Cela permet de contourner la protection en utilisant des caractères encodés.

### Code vulnérable
```python
def is_safe_path(file_path):
    """Fonction de sécurité vulnérable"""
    if '../' in file_path:  # Filtre basique
        return False
    return True
```

### Exploitation
1. L'application décodage les paramètres URL avec `urllib.parse.unquote()`
2. Le filtre vérifie seulement la présence de `../`
3. L'encodage URL `%2e%2e%2f` contourne le filtre

## Tests

### Exécution des tests
```bash
cd tests
pip install -r requirements.txt
pytest test_path_traversal.py -v
```

### Tests automatisés
- Accès normal aux fichiers
- Blocage du path traversal basique
- Exploitation avec encodage URL
- Tests de double encodage
- Validation de l'exploit

## Déploiement

### Docker
```bash
docker-compose up -d
```

### Manuel
```bash
cd app
pip install -r requirements.txt
python app.py
```

## Sécurité

### Mesures de protection implémentées
- Filtrage des séquences `../`
- Validation du répertoire de destination
- Contrôle des extensions de fichiers

### Failles de sécurité
- Pas de validation de l'encodage URL
- Filtre trop simple et contournable
- Absence de normalisation robuste des chemins

## Correction

### Solutions recommandées
1. Utiliser `os.path.normpath()` avant la validation
2. Implémenter une liste blanche de chemins autorisés
3. Valider les chemins après décodage URL
4. Utiliser des bibliothèques de sécurité spécialisées
