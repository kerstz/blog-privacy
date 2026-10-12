# app/chat.py
#
# L'ancien handler SocketIO `message` vivait ici. Il etait enregistre APRES
# celui de `app/routes.py` (voir l'ordre des imports dans `app/__init__.py`),
# donc c'est lui qui recevait reellement les evenements — et il :
#   - n'exigeait aucune authentification,
#   - faisait confiance a `data['sender_id']` fourni par le client, ce qui
#     permettait a n'importe qui d'ecrire un message au nom de n'importe quel
#     compte,
#   - enregistrait le contenu en clair alors que `Message.is_encrypted` vaut
#     True par defaut.
#
# Le handler authentifie de `app/routes.py` (`handle_message`) est desormais le
# seul enregistre pour cet evenement. Ne pas reintroduire de handler `message`
# ici sans verifier `current_user`.
