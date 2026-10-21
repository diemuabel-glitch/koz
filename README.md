# KOZ

KOZ est un réseau social en français avec un fil de publications, des vidéos, des profils, une messagerie privée et des appels audio/vidéo.

## Déploiement

Le site est hébergé par GitHub Pages depuis la branche `main` de ce dépôt : https://diemuabel-glitch.github.io/koz/

La configuration Supabase utilise une clé publique. N’y ajoutez jamais de clé `service_role`, de mot de passe ou de secret TURN.

## Supabase

Exécutez les migrations dans `supabase/migrations/` dans l’ordre chronologique, puis ajoutez l’URL du site comme URL de redirection dans les réglages Auth du projet Supabase.

## Local

Servez le dossier à l’aide d’un serveur HTTP, par exemple `py -m http.server 8000`, puis ouvrez `http://localhost:8000`.
