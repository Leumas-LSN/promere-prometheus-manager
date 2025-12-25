# Recherche : Configuration Alertmanager

Ce document résume le fonctionnement et la syntaxe de configuration d'Alertmanager, avec un focus spécifique sur SMTP et Webhooks, pour guider l'implémentation dans Promere.

## 1. Structure Générale

Le fichier `alertmanager.yml` contient plusieurs sections clés :
*   `global` : Paramètres par défaut (notamment SMTP).
*   `route` : Arbre de routage des alertes (définit qui reçoit quoi).
*   `receivers` : Définition des canaux de notification (email, webhook, slack, etc.).
*   `inhibit_rules` : Règles de suppression de bruit.

## 2. Configuration SMTP (Email)

L'envoi d'emails se configure généralement en deux parties :
1.  **Global** : Le serveur SMTP (smarthost), l'authentification et l'expéditeur par défaut.
2.  **Receiver** : L'adresse du destinataire.

### Syntaxe Global (extrait)
```yaml
global:
  smtp_smarthost: 'smtp.example.com:587'
  smtp_from: 'alertmanager@example.com'
  smtp_auth_username: 'user@example.com'
  smtp_auth_password: 'password'
  smtp_require_tls: true
```

### Syntaxe Receiver
```yaml
receivers:
- name: 'email-team-A'
  email_configs:
  - to: 'team-a@example.com'
    send_resolved: true
```

### Best Practices
*   Utiliser le port 587 pour TLS.
*   Ne pas exposer le mot de passe en clair dans l'UI (le masquer par `*****` si non modifié).
*   Permettre de définir un `smtp_from` clair.

## 3. Configuration Webhook

Les webhooks permettent d'envoyer les alertes (format JSON) vers un système tiers (Microsoft Teams, Discord, Service d'incident, etc.).

### Syntaxe Receiver
```yaml
receivers:
- name: 'webhook-team-A'
  webhook_configs:
  - url: 'http://api.example.com/alerts'
    send_resolved: true
```

### Format du payload
Le payload JSON contient la liste des alertes, leurs status (`firing` ou `resolved`), et les labels communs.

## 4. Implémentation dans Promere

### Architecture
*   **Fichier** : Monter `alertmanager.yml` dans le conteneur Promere.
*   **Parsing** : Lire le YAML, modifier les objets Python/Dict, réécrire le YAML.
*   **Sécurité** : Attention aux mots de passe SMTP lors de la lecture/écriture.

### Interface Utilisateur (Idées)

Créer une page "Notification Channels" ou "Alertmanager" avec 3 sections :

1.  **Global SMTP Settings**
    *   Formulaire simple : Host, Port, Username, Password, From Address.
    *   Bouton "Save SMTP Config".

2.  **Receivers (Destinataires)**
    *   Liste des receivers existants.
    *   Bouton "Add Receiver".
    *   Modal de création :
        *   Nom du receiver (ex: `team-ops-email`).
        *   Type : Dropdown (Email, Webhook).
        *   Champs dynamiques selon le type (Email: `to`; Webhook: `url`).

3.  **Routing (Simplifié)**
    *   Sélection du "Default Receiver" (le receiver par défaut dans la racine `route`).
    *   *(Avancé : ne pas implémenter l'arbre de routage complexe pour l'instant, trop risqué pour l'UX).*

### Actions Backend
*   `GET /alertmanager/config` : Renvoie la config actuelle.
*   `POST /alertmanager/config/global` : Met à jour la section `global`.
*   `POST /alertmanager/receivers` : Ajoute/Modifie un receiver.
*   `POST /alertmanager/reload` : Déclenche le reload d'Alertmanager (`/-/reload`).
