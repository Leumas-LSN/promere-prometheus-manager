# Recherche : Prometheus Alerting & Alertmanager

Ce document résume le fonctionnement des règles d'alertes Prometheus et d'Alertmanager, ainsi que des propositions de fonctionnalités pour l'application Promere.

## 1. Prometheus Alert Rules

Les règles d'alerte permettent à Prometheus de déclencher des alertes basées sur des expressions PromQL. Elles sont définies dans des fichiers de configuration (généralement `.yml` ou `.yaml`) chargés par le serveur Prometheus.

### Structure d'un fichier de règles

```yaml
groups:
  - name: <string>  # Nom du groupe de règles (obligatoire, doit être unique dans le fichier)
    rules:
      - alert: <string> # Nom de l'alerte
        expr: <string>  # Expression PromQL (condition de déclenchement)
        for: <duration> # Durée pendant laquelle la condition doit être vraie avant de déclencher (optionnel, ex: 5m)
        labels:         # Labels additionnels attachés à l'alerte
          severity: critical
          team: devops
        annotations:    # Informations descriptives (peuvent utiliser des templates Go)
          summary: "Instance {{ $labels.instance }} down"
          description: "Le serveur {{ $labels.instance }} ne répond plus depuis 5 minutes."
```

### Concepts clés
*   **Evaluation** : Prometheus évalue les règles à intervalle régulier (`evaluation_interval` dans `prometheus.yml`).
*   **Pending vs Firing** :
    *   **Pending** : L'expression est vraie, mais la durée `for` n'est pas encore atteinte.
    *   **Firing** : L'expression est vraie depuis au moins la durée `for`. L'alerte est envoyée à Alertmanager.
*   **Templating** : Les annotations peuvent utiliser des variables comme `{{ $value }}` (valeur de l'expression) ou `{{ $labels.<label_name> }}`.

## 2. Alertmanager

Alertmanager reçoit les alertes "Firing" de Prometheus et gère leur cycle de vie. Il ne *génère* pas d'alertes (sauf exception comme Dead Man's Switch), il les traite.

### Rôle et Fonctionnalités
*   **Grouping** : Regroupe des alertes similaires en une seule notification (ex: 10 serveurs tombent en même temps -> 1 email avec la liste, au lieu de 10 emails).
*   **Inhibition** : Supprime des notifications si certaines autres alertes sont déjà actives (ex: Si le switch réseau est DOWN, ne pas sonner pour tous les serveurs derrière).
*   **Silencing** : Permet de rendre silencieuse une alerte pour une durée donnée (maintenance prévue). Se fait via l'API ou l'UI d'Alertmanager.
*   **Routing** : Dirige les alertes vers les bons récepteurs (Slack, Email, PagerDuty, Webhook) en fonction des labels.

## 3. Idées de fonctionnalités pour Promere

L'objectif est d'ajouter un CRUD (Create, Read, Update, Delete) pour les règles d'alerte dans Promere.

### Architecture proposée
Promere gère déjà des fichiers JSON pour les targets. Pour les alertes, il devra gérer des fichiers YAML.
*   **Stockage** : Utiliser un dossier dédié (ex: `/config/rules/`) monté dans le conteneur Prometheus.
*   **Configuration Prometheus** : S'assurer que `prometheus.yml` inclut ce dossier via `rule_files: ["/config/rules/*.yml"]`.

### Fonctionnalités MVP (Minimum Viable Product)

1.  **Liste des Alertes (Read)**
    *   Lister les groupes d'alertes existants.
    *   Afficher les détails (nom, expression, sévérité).
    *   Indicateur visuel si l'alerte est syntaxiquement valide (via validation simple ou retour API Prometheus).

2.  **Ajout/Édition d'Alertes (Create/Update)**
    *   Formulaire intuitif pour créer une règle :
        *   Nom de l'alerte.
        *   Expression PromQL (champ texte ou éditeur avec coloration syntaxique simple).
        *   Durée (`for`).
        *   Labels (interface clé/valeur dynamique).
        *   Annotations (interface clé/valeur dynamique, champs pré-remplis pour Summary/Description).
    *   Validation : Vérifier que le YAML généré est valide avant l'écriture.

3.  **Suppression (Delete)**
    *   Supprimer une règle spécifique d'un groupe.
    *   Supprimer un groupe entier.

4.  **Intégration Prometheus**
    *   Bouton "Reload Configuration" (déjà existant, à réutiliser) pour appliquer les nouvelles règles sans redémarrer.
    *   Vérification de l'état des règles via l'API Prometheus (`/api/v1/rules`) pour voir si elles sont chargées correctement (State: OK/Err).

### Fonctionnalités Avancées (v2)

*   **Intégration Alertmanager** :
    *   Visualiser les "Silences" actifs.
    *   Créer un Silence directement depuis Promere pour une alerte donnée.
*   **Simulateur PromQL** : Tester l'expression `expr` contre les données actuelles de Prometheus pour voir si elle retournerait des résultats.
*   **Import/Export** : Importer des règles depuis des bibliothèques communes (ex: Awesome Prometheus Alerts).

### Risques et Contraintes
*   **Syntaxe YAML** : La génération de YAML doit être rigoureuse (indentation). Utiliser une librairie comme `PyYAML`.
*   **Permissions** : Promere doit avoir les droits d'écriture sur le dossier des règles monté dans le conteneur.
*   **Validation PromQL** : Difficile de valider parfaitement une expression PromQL côté Promere sans l'envoyer à Prometheus. On peut utiliser l'API de query pour un "dry run".
