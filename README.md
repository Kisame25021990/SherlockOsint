# Sherlock OSINT

Application web d'OSINT multi-modules : interface navigateur, résultats en temps réel et moteur Sherlock pour la recherche de pseudonymes sur plus de 400 sites.

## Installation

```bash
python3 -m venv .venv
.venv/bin/python -m ensurepip --upgrade
.venv/bin/python -m pip install -r requirements.txt
```

Copier `.env.example` vers `.env` et adapter les variables souhaitées. Le fichier `.env` est chargé automatiquement au démarrage du serveur (les variables déjà exportées dans le shell restent prioritaires).

## Lancement

```bash
.venv/bin/python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Ouvrir ensuite http://127.0.0.1:8000.

## Exposition sur Internet

Le service n'a pas d'autorisation par utilisateur : définissez **obligatoirement** `OSINT_AUTH_USER` et `OSINT_AUTH_PASSWORD` dans `.env` avant toute exposition. L'authentification Basic protège alors l'interface et toutes les routes API, sauf `/api/health`.

Faites terminer TLS par un reverse proxy (Caddy, nginx…) et laissez uvicorn écouter sur `127.0.0.1`. Renseignez `OSINT_CORS_ORIGINS` avec l'origine publique exacte si l'interface est servie depuis un autre domaine.

## Utilisation

1. Saisir une cible et sélectionner un ou plusieurs modules.
2. Lancer l'analyse : les résultats arrivent en direct via Server-Sent Events.
3. Consulter l'historique, réouvrir un scan ou exporter en JSON/CSV.

## Modules

- `username` : 400+ réseaux sociaux via Sherlock (liste de sites embarquée par défaut)
- `email` : syntaxe, MX, Gravatar ; clé optionnelle `HIBP_API_KEY`
- `domain` : DNS, RDAP, sous-domaines crt.sh ; clé optionnelle `VIRUSTOTAL_API_KEY`
- `ip` : géolocalisation, ASN, reverse DNS ; clé optionnelle `SHODAN_API_KEY`
- `phone` : validité, pays, opérateur, type de ligne
- `geolocation` : accepte une IP ou un domaine, résout l'adresse puis affiche pays, ville, FAI, fuseau horaire et coordonnées

Les géolocalisations alimentent automatiquement une carte interactive (Leaflet embarqué, tuiles CARTO/OpenStreetMap) dans le panneau de résultats. Si les tuiles sont inaccessibles, les coordonnées sont affichées en texte.

## API

- `GET /api/health` : état du service
- `GET /api/modules` : liste des modules
- `POST /api/scans` : créer un scan (corps : `target`, `modules`, `options`)
- `GET /api/scans/{id}/stream` : flux SSE des événements
- `GET /api/scans/{id}` : résultat complet
- `GET /api/scans` : historique
- `DELETE /api/scans/{id}` : suppression
- `GET /api/scans/{id}/export?format=json` ou `format=csv` : export

Les options acceptent `timeout`, `sites`, `include_nsfw` et `proxy`.

## Tests et lint

Depuis la racine du projet :

```bash
.venv/bin/python -m pytest
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

## Limites

Recherche uniquement sur des données publiques. Les correspondances sont des candidates à vérifier manuellement, pas des preuves d'identité.
