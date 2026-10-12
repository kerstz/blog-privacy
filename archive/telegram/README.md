# Pont Telegram — archivé

Retiré du code actif le 27 août 2026. Conservé ici en entier, pas supprimé.

## Pourquoi

Quand le pont était configuré, le serveur **déchiffrait** chaque message
d'utilisateur avant de l'envoyer aux serveurs de Telegram, accompagné du pseudo
et de l'identifiant de son auteur, pièces jointes comprises. Le formulaire de
contact y recopiait aussi le nom, l'adresse e-mail et le texte du visiteur.

Sur une plateforme dont la promesse est le chiffrement des échanges avec
l'administration, cela déplaçait la confidentialité hors du périmètre contrôlé
par l'opérateur — et la personne qui écrivait n'en était jamais informée.

Le pont était désactivé par défaut (il exigeait `TELEGRAM_BOT_TOKEN` et
`TELEGRAM_ADMIN_CHAT_ID`), mais rien n'empêchait de l'activer sans mesurer ce
que cela impliquait.

## Contenu

| Fichier | Contenu |
|---|---|
| `telegram_bridge.py` | Les 71 blocs extraits de `app/routes.py` : long-polling, panneau d'administration, authentification par PIN, journal d'audit, envoi de photos et documents. |

Ce fichier **n'est pas importable tel quel**. Il référence `app`, `db`, les
modèles, et des fonctions restées dans `app/routes.py`. C'est une archive de
lecture, pas un module.

## Ce qui a été retiré du code actif

- `app/routes.py` — hook `before_request` du poller, remplacé par
  `publish_due_scheduled_posts()` qui ne garde que la publication des articles
  programmés
- `chat()`, `handle_message()` — appels à `notify_admin_telegram_new_message`
- `admin_chat_user()` — `telegram_fetch_updates()` avant rendu, et la variable
  de gabarit `telegram_bridge_enabled`
- `contact()` — recopie du message de contact vers Telegram
- `wait_for_conversation_message()` — sondage Telegram pendant l'attente SSE
- `app/templates/admin_chat_user.html` — bandeau « Telegram bridge active »
- `.env.example` — les six variables `TELEGRAM_*`
- imports devenus inutiles dans `routes.py` : `sqlite3`, `requests`, `Thread`,
  `piexif`

L'API mobile d'administration (Basic Auth + flux SSE) est **conservée** : elle
reste dans le périmètre du serveur et ne transite par aucun tiers.

## Si vous le remettez en service

1. Recréer les imports et les points d'ancrage listés ci-dessus.
2. Restaurer les variables d'environnement : `TELEGRAM_BOT_TOKEN`,
   `TELEGRAM_ADMIN_CHAT_ID`, `TELEGRAM_ADMIN_USER_ID`, `TELEGRAM_ADMIN_PIN`,
   `TELEGRAM_ADMIN_SESSION_TTL`, `TELEGRAM_AUDIT_CHAT_ID`.
3. **Avertir les utilisateurs dans l'interface de chat** que leurs messages sont
   relayés vers Telegram. C'est la condition qui manquait.

La base annexe `instance/telegram_users.db`, si elle existe, recense les chats
Telegram connus. Elle n'est plus lue ni écrite.
