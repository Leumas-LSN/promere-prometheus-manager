# Plan d'Évolution - Promere

Ce document recense les fonctionnalités futures identifiées pour enrichir l'application Promere.

## 1. 🧙‍♂️ Assistant d'Installation d'Exporters ("Target Wizard")
Faciliter l'ajout de nouvelles cibles pour les utilisateurs ne maîtrisant pas Prometheus.
*   **Concept :** Bibliothèque de "Presets" (Linux, Docker, Postgres, Nginx...).
*   **Fonctionnement :**
    1.  L'utilisateur choisit un type (ex: "Linux Server").
    2.  L'application génère une commande (curl/docker) à exécuter sur la machine cible.
    3.  L'application pré-configure le job de scrape correspondant.

## 2. ⚡ Gestion des "Recording Rules"
Optimiser les performances et permettre des requêtes historiques rapides.
*   **Objectif :** Créer/Gérer des règles qui pré-calculent des expressions PromQL coûteuses.
*   **Implémentation :** Interface similaire aux Alert Rules, mais stockée dans un fichier `recording_rules.yml`.

## 3. 🧩 Visual Query Builder (No-Code PromQL)
Rendre le langage PromQL accessible aux débutants via une interface graphique.
*   **Concept :** Un constructeur de requête visuel.
*   **UX :**
    *   Sélection de la métrique (Dropdown/Autocomplétion).
    *   Ajout de filtres (Labels).
    *   Application de fonctions (Rate, Sum, Avg).
    *   Génération automatique de la syntaxe PromQL dans l'éditeur.

## 4. 🚦 Status Page "Publique" (Vue Management)
Une vue simplifiée pour les non-techniciens.
*   **Concept :** Dashboard minimaliste "Feu tricolore".
*   **Contenu :** Statut global des services critiques (Vert/Rouge).
*   **Accès :** Potentiellement accessible sans authentification complète (ou via un lien partagé).

## 5. 🔍 Intégration Logs (Loki "Light")
Corréler les métriques et les logs.
*   **Objectif :** Voir ce qu'il s'est passé au moment d'une alerte.
*   **Fonctionnalité :** Bouton "View Logs" contextuel (basé sur les labels de l'alerte/target) qui interroge une instance Loki.
