# Anonymat et vie privée — audit et plan d'amélioration

Audit du 27 août 2026, sur la branche `main` (commit de départ `0fab494`).

Le projet se présente comme une plateforme de blog *privacy-focused*. Les briques
défensives annoncées sont bien là — chiffrement Fernet, TOTP, CSRF, bcrypt,
suppression EXIF, rate limiting. L'audit a porté sur ce qui se passe réellement à
l'exécution, et plusieurs de ces briques ne tenaient pas leur promesse : certaines
étaient contournées par un autre chemin de code, une autre était activement
inversée, et le site contactait cinq domaines tiers à chaque page vue.

Ce document liste ce qui a été trouvé, ce qui a été corrigé dans cette passe, et
ce qui reste à faire.

> Mise à jour (audit 2026-10-16) : Flask-SocketIO et tout le WebSocket ont depuis été
> retirés de l'application ; les passages ci-dessous qui les mentionnent sont
> conservés comme historique.

---

## 1. Ce qui a été corrigé

### 1.1 Fuites de confidentialité entre utilisateurs

**La page `/chat` servait toutes les conversations à tout le monde.**
`Message.query.order_by(...).all()` ne filtrait sur aucun destinataire : n'importe
quel compte connecté lisait l'intégralité des échanges privés entre les autres
utilisateurs et l'administration. La requête est désormais bornée à la
conversation entre l'utilisateur courant et l'admin.
→ `app/routes.py`, route `chat()`

**Le handler WebSocket acceptait un expéditeur arbitraire.**
`app/chat.py` enregistrait un handler `message` *après* celui de `routes.py` ;
c'est donc lui qui recevait les événements. Il n'exigeait aucune
authentification et faisait confiance au champ `sender_id` envoyé par le client —
n'importe qui pouvait écrire un message au nom de n'importe quel compte, et le
contenu était stocké en clair. Le fichier ne contient plus que la note expliquant
pourquoi, et le handler authentifié de `routes.py` est seul en place.
→ `app/chat.py`, `app/routes.py::handle_message`

**Chaque message privé était rediffusé à tous les clients WebSocket.**
Le handler faisait `emit(..., broadcast=True)` avec le pseudo de l'auteur, et la
réponse de l'admin dans `admin_chat_user` faisait un `socketio.emit` sans salon.
Les deux diffusions sont supprimées ; l'expéditeur reçoit seul son accusé de
réception.

**Les pièces jointes du chat étaient publiques.**
`/uploads/<filename>` servait n'importe quel fichier sans authentification, et le
nom était devinable : `chat_<user_id>_admin_<horodatage>_<nom d'origine>`. Une
pièce jointe est maintenant réservée aux deux correspondants et aux admins, les
noms sont des UUID aléatoires, et seule l'extension est conservée.

### 1.2 Chiffrement des messages

**Les messages du web étaient stockés en clair.** La route `/chat` faisait
`Message(content=...)` sans passer par `set_encrypted_content()`, alors que
`is_encrypted` vaut `True` par défaut dans le modèle. Le pont Telegram, lui,
chiffrait correctement. Les deux chemins du web sont alignés.

**Le déchiffrement échouait silencieusement sur une partie des messages.**
`encrypt_message` produit du base64 *urlsafe* (alphabet `-` et `_`), mais le
pré-filtre `_is_base64` n'acceptait que l'alphabet standard `+/`. Dès qu'un jeton
contenait un `-` ou un `_`, le message était renvoyé chiffré à l'affichage. Le
pré-filtre est supprimé : on tente le déchiffrement, et on retombe sur la valeur
brute uniquement en cas d'échec (compatibilité avec les messages écrits en clair
avant).

**Le chiffrement échouait en clair.** `encrypt_message` rattrapait toute exception
et retournait le message *non chiffré*, qui partait tel quel en base. Une erreur
de configuration produisait donc une conversation en clair que l'utilisateur
croyait protégée. La fonction laisse maintenant remonter l'exception.

### 1.3 Fuites vers des tiers

Un blog dédié à l'anonymat qui charge des ressources distantes communique à
chaque tiers l'adresse IP du lecteur, son User-Agent et l'URL consultée. Cinq
origines étaient contactées :

| Origine | Où | Statut |
|---|---|---|
| `fonts.googleapis.com` / `fonts.gstatic.com` | `layout.html`, `admin_dashboard.html` | supprimé |
| `stackpath.bootstrapcdn.com` | `admin_layout.html`, `admin_dashboard.html` | supprimé, remplacé par `static/css/admin.css` |
| `cdnjs.cloudflare.com` (Font Awesome) | `admin_dashboard.html` | supprimé — aucune classe `fa-` n'était utilisée |
| `code.jquery.com`, `cdn.jsdelivr.net` | `admin_dashboard.html` | supprimé — non utilisés par la page |
| `trocador.app` | `donate.html` | passé en chargement sur demande |

Les piles de repli déjà présentes dans `style.css` (Georgia, `system-ui`,
`ui-monospace`) prennent le relais des polices distantes.

Le widget de don Trocador était un `<iframe>` posé directement dans la page : il
faisait contacter Trocador par le navigateur de **tout** lecteur ouvrant `/donate`,
même sans intention de donner. Il ne se charge plus que sur clic explicite
(`/donate?embed=1`), avec un avertissement, et la CSP n'est assouplie que pour
cette réponse.

### 1.4 XSS stockée

`parse_bbcode()` n'échappait pas son entrée, et les commentaires sont stockés
*déjà convertis en HTML* puis rendus avec `| safe`. Un commentaire contenant
`<script>` s'exécutait donc chez tous les lecteurs de l'article — sur ce type de
site, une XSS est directement une attaque de désanonymisation. Le texte est
maintenant échappé avant conversion.

Même problème dans le chat : `chat.html` et `admin_chat.html` rendaient le contenu
des messages avec `| safe`, ce qui donnait à n'importe quel utilisateur une XSS
dirigée vers l'administrateur. Le filtre est retiré.

Le SVG a par ailleurs été retiré des extensions d'image acceptées : servi depuis
notre propre origine, un SVG peut embarquer un `<script>`.

### 1.5 Métadonnées d'images

`modify_exif_data()` faisait l'inverse de ce que son usage laissait croire : elle
*ajoutait* des tags EXIF (`Make: Modified`, `Software: ChatUploader`), ne vidait
que le bloc GPS, et réenregistrait **tout** fichier en JPEG — y compris les PNG.
Elle est remplacée par `strip_image_metadata()`, qui reconstruit l'image à partir
de ses seuls pixels : aucun bloc de métadonnées ne survit, le format d'origine est
conservé, et une image dont le nettoyage échoue est supprimée plutôt que servie.

### 1.6 En-têtes HTTP et cookies

- CSP resserrée : plus aucune origine tierce, `frame-ancestors 'none'`,
  `object-src 'none'`, `frame-src 'none'`, et `'unsafe-eval'` retiré de
  `script-src`.
- `Referrer-Policy: no-referrer` (contre `strict-origin-when-cross-origin`) : plus
  aucune URL de ce site ne fuite vers un site externe quand un lecteur suit un lien.
- `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy`,
  `Cross-Origin-Resource-Policy`, `Permissions-Policy` élargie.
- HSTS envoyé uniquement sur une connexion HTTPS réelle (ou via `FORCE_HSTS`).
- En-tête `Server` neutralisé.
- `SESSION_COOKIE_SECURE` passe à `true` **par défaut** — il faut désormais poser
  `false` explicitement pour développer en HTTP, au lieu d'oublier de l'activer en
  production. `SameSite=Strict`, préfixe `__Host-`, cookie `remember_me`
  aligné et limité à 7 jours.
- `/robots.txt` décourage l'indexation de `/chat`, `/uploads/`, `/profile/`, `/api/`.

### 1.7 Le pont Telegram, archivé

Quand `TELEGRAM_BOT_TOKEN` et `TELEGRAM_ADMIN_CHAT_ID` étaient renseignés, le
contenu **déchiffré** de chaque message utilisateur, son pseudo et son `user_id`
partaient vers les serveurs de Telegram, pièces jointes comprises. Le formulaire
de contact y recopiait aussi le nom, l'adresse e-mail et le texte du visiteur.
Sur une plateforme dont la promesse est le chiffrement des échanges avec
l'administration, cela déplaçait la confidentialité hors du périmètre contrôlé
par l'opérateur — sans que la personne qui écrit en soit jamais informée.

Le pont est retiré du code actif et conservé en lecture dans
`archive/telegram/`, avec un README expliquant ce qu'il faisait, pourquoi il a
été retiré et ce qu'il faudrait rétablir pour le remettre en service. 71 blocs
ont été extraits ; `routes.py` passe de 3 537 à 1 917 lignes.

Points d'ancrage supprimés : le hook `before_request` du poller (remplacé par
`publish_due_scheduled_posts()`, qui ne garde que la publication programmée),
les appels à `notify_admin_telegram_new_message` dans `chat()` et
`handle_message()`, la synchronisation avant rendu dans `admin_chat_user()`, la
recopie du message de contact, le sondage pendant l'attente SSE, le bandeau
« Telegram bridge active » du gabarit, les six variables `TELEGRAM_*` de
`.env.example`, et les imports devenus inutiles (`sqlite3`, `requests`,
`Thread`, `piexif`).

L'API mobile d'administration (Basic Auth + flux SSE) est **conservée** : elle
reste dans le périmètre du serveur et ne transite par aucun tiers.

La base annexe `instance/telegram_users.db` (8 Ko) recense les chats Telegram
connus — pseudos et derniers messages. Elle n'est plus lue ni écrite, et n'a pas
été supprimée : c'est une décision à prendre, pas une conséquence technique.

### 1.8 Journalisation et adresses IP

Le serveur écrivait une ligne de log par requête, contenant l'adresse IP du
visiteur — la fuite la plus banale sur ce type de site, et celle qui survit le
plus longtemps. Un filtre de journalisation masque désormais les IPv4 et IPv6
dans tous les journaux (`LOG_CLIENT_IP=true` pour rétablir en cas de débogage).

Le limiteur de débit stockait `ip:<adresse>` en clair en mémoire. Il utilise
maintenant un condensat BLAKE2b clé par un sel régénéré à chaque démarrage : deux
visiteurs restent distinguables, aucune adresse IP ne subsiste.

`ProxyFix` est disponible via `TRUST_PROXY=true`. Sans lui, derrière un reverse
proxy ou un service onion, `request.remote_addr` vaut `127.0.0.1` pour tout le
monde et le rate limiting s'applique globalement au lieu de par visiteur.

### 1.9 Comptes

- Mot de passe : 12 caractères minimum (aucune longueur minimale auparavant),
  refus des mots de passe les plus évidents et de ceux contenant le pseudo.
- Énumération de comptes au chronomètre supprimée sur `/login` : une vérification
  bcrypt factice égalise le temps de réponse quand le compte n'existe pas.
- `.env` est passé en permissions `600` (il était lisible par le groupe et les autres).

### 1.10 Deux pannes préexistantes, rencontrées en vérifiant

Aucune n'est liée aux corrections ci-dessus ; les deux étaient dans l'état
initial du dépôt.

- **Le formulaire de contact renvoyait une erreur 500 à chaque envoi.**
  `ContactForm` utilise le validateur `Email()` de WTForms, qui exige le paquet
  `email_validator` — absent de `requirements.txt`. Ajouté et installé.
- **`python wsgi.py`, la commande de démarrage du README, ne lançait rien.**
  Le fichier se contentait d'exposer `application`. Un bloc
  `if __name__ == '__main__'` avec `socketio.run()` a été ajouté —
  `app.run()` ne conviendrait pas, il ne sert pas le WebSocket.

---

## 2. Ce qui reste à faire

Classé par rapport valeur/effort. Rien de tout cela n'est bloquant pour tourner,
mais les trois premiers points sont ceux qui limitent réellement le niveau
d'anonymat atteignable aujourd'hui.

### 2.1 Le chiffrement des messages n'est pas de bout en bout

C'est la limite structurelle du modèle actuel, et elle mérite d'être écrite
clairement quelque part de visible pour les utilisateurs. `ENCRYPTION_KEY` vit sur
le serveur, à côté de la base ; l'application déchiffre à chaque affichage. Le
chiffrement protège contre le vol du fichier `blog.db` seul — il ne protège pas
contre quelqu'un qui obtient un accès au serveur, ni contre une réquisition.

Un vrai chiffrement de bout en bout suppose des clés générées et gardées côté
client, ce qui exige JavaScript et entre en tension directe avec le choix
« NoScript friendly » du projet. Le compromis honnête, à court terme, est de ne
pas promettre plus que ce qui est fait : parler de « chiffré au repos » plutôt que
de « chiffré ».

### 2.2 Rétention et effacement

Rien n'expire. Les messages, les pièces jointes, les `ContactMessage` (qui
stockent une adresse e-mail **en clair**) et les `Notification` s'accumulent
indéfiniment. Il n'existe ni suppression de compte ni purge.

À faire :
- purge automatique des messages et pièces jointes au-delà de N jours (une tâche
  planifiée, ou un passage dans le `before_request` existant) ;
- route de suppression de compte (obligation RGPD, art. 17) ;
- chiffrement ou hachage de `ContactMessage.email` ;
- suppression du fichier sur disque quand un message porteur d'une pièce jointe
  est supprimé.

### 2.3 Points concrets, effort faible

| Point | Détail |
|---|---|
| Auto-hébergement des polices | Déposer les `.woff2` de Fraunces et IBM Plex dans `app/static/fonts/` et les déclarer en `@font-face`. Aujourd'hui le rendu retombe sur Georgia/system-ui. |
| `totp_secret` en clair | Le secret TOTP est stocké tel quel. À chiffrer avec le même mécanisme que les messages. |
| Codes de secours 2FA | Aucun. Perdre son téléphone = perdre le compte. |
| Changement de mot de passe | Aucune route. Un compte compromis ne peut pas être repris sans intervention admin. |
| Invalidation de session | Pas de rotation de session à la connexion ni d'invalidation globale. |
| Argon2id | bcrypt reste correct ; Argon2id est le choix recommandé aujourd'hui. |
| `security.txt` | `/.well-known/security.txt` pour recevoir les signalements. |
| CSP par nonce | `'unsafe-inline'` subsiste dans `style-src` et `script-src` à cause des styles et scripts inline. Un nonce par requête les remplacerait. |
| Horodatages | `date_posted` en UTC à la seconde près révèle le rythme de vie de l'auteur. Arrondir à l'heure sur l'affichage public. |
| Énumération à l'inscription | « That username is already taken » confirme l'existence d'un compte. Compromis UX assumé, mais à noter. |

### 2.4 Points d'exploitation

- **Le limiteur de débit est en mémoire du processus.** Avec plusieurs workers
  gunicorn, chacun a son propre compteur : les limites annoncées sont multipliées
  par le nombre de workers. Un stockage partagé (Redis) ou un worker unique est
  nécessaire pour que les chiffres correspondent à la réalité.
- **Base non chiffrée au repos.** SQLCipher, ou à défaut un chiffrement de disque
  sur la machine hôte.
- **Service onion.** Le projet gagnerait un guide de déploiement en `.onion` :
  c'est la configuration où ses choix (pas de JS, BBCode côté serveur, icônes SVG
  locales) prennent tout leur sens. Ne pas activer `FORCE_HSTS` dans ce cas.
- **Aucun test.** Il n'y a pas de répertoire de tests. Les régressions corrigées
  ici — filtrage des conversations, contrôle d'accès aux pièces jointes,
  échappement du BBCode — sont exactement le genre de chose qui revient
  silencieusement. Quelques tests d'intégration `pytest` sur ces trois points
  couvriraient l'essentiel.
- **Chaîne de dépendances.** Ni `pip-audit` ni `bandit` en intégration continue.
- **`routes.py` fait 3 500 lignes** et mélange routes web, bot Telegram, API mobile
  et SSE. Ce n'est pas un problème de sécurité en soi, mais c'est ce qui a permis
  au handler WebSocket dupliqué de passer inaperçu.

### 2.5 Note sur `config.py`

Ce fichier n'est chargé nulle part : `app/__init__.py` renseigne `app.config`
directement et n'appelle jamais `from_object(Config)`. Une note a été ajoutée en
tête du fichier, mais le supprimer ou l'utiliser réellement serait plus sain.

---

## 3. Effets de bord des corrections

À vérifier avant mise en production :

1. **Images distantes dans les articles.** La CSP passe `img-src` à `'self' data:`.
   Un article contenant `[img]https://exemple.com/photo.jpg[/img]` n'affichera plus
   cette image. C'est voulu — une image distante fait fuiter l'IP de chaque lecteur
   vers son hébergeur —, mais les articles existants sont concernés. La solution
   propre est de rapatrier ces images dans `uploads/`.
2. **Cookie `__Host-`.** Il exige HTTPS. En développement HTTP, poser
   `SESSION_COOKIE_SECURE=false` (le nom retombe alors sur `sid`), sinon le
   navigateur rejette le cookie et la connexion échoue silencieusement.
3. **`SameSite=Strict`.** Un visiteur arrivant depuis un lien externe apparaît
   déconnecté jusqu'à sa première navigation interne. Comportement normal.
4. **CKEditor.** `'unsafe-eval'` a été retiré de la CSP. L'éditeur est servi en
   local (`CKEDITOR_SERVE_LOCAL = True`) et ne devrait pas en avoir besoin ; à
   confirmer sur la page de rédaction d'article.
5. **En-tête `Server` en développement.** Le serveur Werkzeug ajoute son propre
   `Server: Werkzeug/... Python/...` au niveau HTTP, après l'application : en
   local, les deux en-têtes apparaissent. Derrière gunicorn en production, seul
   celui de l'application subsiste.
6. **`ENCRYPTION_ITERATIONS`** reste à 100 000 pour ne pas rendre illisibles les
   messages déjà en base. Sur une installation neuve, poser 600 000.
