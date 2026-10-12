"""Textes fixes du site, en francais et en anglais, modifiables depuis l'admin.

Pourquoi pas gettext / Flask-Babel : les catalogues .po sont des fichiers, il
faut les recompiler et redeployer pour changer un mot. La demande ici est que
l'administrateur puisse reecrire n'importe quel texte fixe depuis le panneau
d'administration, dans les deux langues. Un catalogue cle -> valeur stocke en
base repond aux deux besoins avec un seul mecanisme.

Resolution d'un texte, dans l'ordre :
  1. la valeur en base pour la langue courante (ce que l'admin a ecrit) ;
  2. la valeur par defaut ci-dessous pour la langue courante ;
  3. la valeur par defaut en anglais (langue pivot) ;
  4. la cle elle-meme, pour qu'un oubli soit visible plutot que silencieux.

Ajouter un texte : une entree dans DEFAULTS, et `{{ t('ma.cle') }}` dans le
gabarit. Il apparait automatiquement dans l'editeur de l'admin.
"""

import functools
import hashlib
import os
import re

from flask import g, request, session
from sqlalchemy.exc import OperationalError, ProgrammingError

LANGUAGES = {
    'en': 'English',
    'fr': 'Français',
}
DEFAULT_LANGUAGE = 'en'


# Les groupes servent uniquement a organiser l'editeur de l'admin.
GROUPS = [
    ('nav', 'Navigation & footer'),
    ('home', 'Home page'),
    ('posts', 'Articles'),
    ('about', 'About page'),
    ('contact', 'Contact page'),
    ('auth', 'Sign in & register'),
    ('account', 'Account & password'),
    ('chat', 'Chat'),
    ('profile', 'Profile'),
    ('edit', 'Edit profile'),
    ('totp', 'Two-factor authentication'),
    ('donate', 'Donate page'),
    ('misc', 'Notifications & profile'),
]

# Textes longs : rendus via le parseur BBCode (echappe puis mis en forme), les
# sauts de ligne deviennent des paragraphes. Les autres sont du texte simple.
RICH_KEYS = {
    'home.hero.body',
    'home.contact.body',
    'about.body',
    'contact.body',
    'donate.body',
}


DEFAULTS = {
    # ---------------------------------------------------------------- nav
    'nav.about':        {'en': 'About',            'fr': 'À propos'},
    'nav.contact':      {'en': 'Contact',          'fr': 'Contact'},
    'nav.register':     {'en': 'Register',         'fr': 'Créer un compte'},
    'nav.login':        {'en': 'Login',            'fr': 'Connexion'},
    'nav.logout':       {'en': 'Log out',          'fr': 'Se déconnecter'},
    'nav.profile':      {'en': 'Profile',          'fr': 'Profil'},
    'nav.notifications': {'en': 'Notifications',   'fr': 'Notifications'},
    'nav.admin':        {'en': 'Admin panel',      'fr': 'Administration'},
    'nav.donate':       {'en': 'Support the blog', 'fr': 'Soutenir le blog'},
    'nav.language':     {'en': 'Language',         'fr': 'Langue'},

    # --------------------------------------------------------------- home
    'home.hero.eyebrow': {'en': 'Written when the house is quiet',
                          'fr': 'Écrit quand la maison est calme'},
    'home.hero.title':   {'en': 'Notes from the small hours.',
                          'fr': 'Notes des petites heures.'},
    'home.hero.body':    {'en': 'Whatever I am turning over when I cannot sleep — music, code, '
                                'privacy, the usual circling. Nothing here tracks you, counts '
                                'you, or tells anyone you came.',
                          'fr': 'Ce que je retourne dans ma tête quand je n\'arrive pas à dormir — '
                                'musique, code, vie privée, les tours habituels. Rien ici ne te '
                                'piste, ne te compte, ni ne dit à quiconque que tu es passé.'},
    'home.hero.cta':     {'en': 'Start reading',   'fr': 'Commencer à lire'},
    'home.recent':       {'en': 'Recent entries',  'fr': 'Dernières entrées'},
    'home.empty':        {'en': 'Nothing written yet.',
                          'fr': 'Rien d\'écrit pour l\'instant.'},
    'home.contact.title': {'en': 'Say something',  'fr': 'Dis quelque chose'},
    'home.contact.body': {'en': 'If any of this landed, I would rather hear it than not. '
                                'I read everything and I reply.',
                          'fr': 'Si quelque chose ici t\'a parlé, je préfère le savoir. '
                                'Je lis tout et je réponds.'},
    'home.contact.cta':  {'en': 'Send a message',  'fr': 'Envoyer un message'},

    # -------------------------------------------------------------- posts
    'posts.all':         {'en': 'All entries',     'fr': 'Toutes les entrées'},
    'posts.read':        {'en': 'Read',            'fr': 'Lire'},
    'posts.empty':       {'en': 'No posts available yet.',
                          'fr': 'Aucun article pour le moment.'},
    'posts.views':       {'en': 'views',           'fr': 'vues'},
    'posts.comments':    {'en': 'Comments',        'fr': 'Commentaires'},
    'posts.comment.add': {'en': 'Post comment',    'fr': 'Publier le commentaire'},
    'posts.comment.placeholder': {'en': 'Write a comment…',
                                  'fr': 'Écrire un commentaire…'},
    'posts.comment.empty': {'en': 'No comments yet.',
                            'fr': 'Aucun commentaire pour l\'instant.'},
    'posts.comment.login': {'en': 'Sign in to leave a comment.',
                            'fr': 'Connecte-toi pour laisser un commentaire.'},
    'posts.reply':       {'en': 'Reply',           'fr': 'Répondre'},
    'posts.edit':        {'en': 'Edit',            'fr': 'Modifier'},
    'posts.delete':      {'en': 'Delete',          'fr': 'Supprimer'},

    # -------------------------------------------------------------- about
    'about.eyebrow':     {'en': 'About',           'fr': 'À propos'},
    'about.title':       {'en': 'About this blog', 'fr': 'À propos de ce blog'},
    'about.body':        {'en': '', 'fr': ''},   # rempli au premier demarrage

    # ------------------------------------------------------------ contact
    'contact.eyebrow':   {'en': 'Contact',         'fr': 'Contact'},
    'contact.title':     {'en': 'Let\'s stay in touch',
                          'fr': 'Restons en contact'},
    'contact.body':      {'en': 'You can send me an email if you prefer a more detailed message.',
                          'fr': 'Tu peux m\'écrire un e-mail si tu préfères un message plus détaillé.'},
    'contact.name':      {'en': 'Your name',       'fr': 'Ton nom'},
    'contact.email':     {'en': 'Your email',      'fr': 'Ton e-mail'},
    'contact.message':   {'en': 'Your message',    'fr': 'Ton message'},
    'contact.send':      {'en': 'Send message',    'fr': 'Envoyer le message'},
    'contact.email_cta': {'en': 'Send an email',   'fr': 'Envoyer un e-mail'},
    'contact.subtitle':  {'en': 'If you have a question, feedback, or just want to talk, '
                                'you are welcome here.',
                          'fr': 'Une question, un retour, ou juste l\'envie de parler : '
                                'tu es le bienvenu.'},
    'contact.email_heading': {'en': 'Email',       'fr': 'E-mail'},
    # Adresse a renseigner depuis l'admin. La valeur d'origine du gabarit
    # (contact@techblog.example) etait un exemple, pas une vraie boite.
    'contact.email_address': {'en': '',            'fr': ''},
    'contact.chat_heading': {'en': 'Live chat',    'fr': 'Chat en direct'},
    'contact.chat_body': {'en': 'If you want a faster reply, use the chat. I usually answer '
                                'there quicker than by email.',
                          'fr': 'Pour une réponse plus rapide, passe par le chat. '
                                'J\'y réponds généralement plus vite que par e-mail.'},
    'contact.footer':    {'en': 'Thanks for reaching out, I really appreciate it.',
                          'fr': 'Merci d\'avoir pris le temps d\'écrire, ça compte.'},
    'contact.chat_cta':  {'en': 'Open the chat',   'fr': 'Ouvrir le chat'},

    # --------------------------------------------------------------- auth
    'auth.login.title':  {'en': 'Sign in',         'fr': 'Connexion'},
    'auth.login.submit': {'en': 'Sign in',         'fr': 'Se connecter'},
    'auth.login.no_account': {'en': 'No account yet?',
                              'fr': 'Pas encore de compte ?'},
    'auth.login.create': {'en': 'Create one',      'fr': 'En créer un'},
    'auth.register.title': {'en': 'Create account','fr': 'Créer un compte'},
    'auth.register.submit': {'en': 'Register',     'fr': 'S\'inscrire'},
    'auth.register.has_account': {'en': 'Already have an account?',
                                  'fr': 'Tu as déjà un compte ?'},
    'auth.register.signin': {'en': 'Sign in here', 'fr': 'Connecte-toi ici'},
    'auth.username':     {'en': 'Username',        'fr': 'Nom d\'utilisateur'},
    'auth.password':     {'en': 'Password',        'fr': 'Mot de passe'},
    'auth.password_confirm': {'en': 'Confirm password',
                              'fr': 'Confirmer le mot de passe'},
    'auth.totp.title':   {'en': 'Two-factor authentication',
                          'fr': 'Authentification à deux facteurs'},
    'auth.totp.body':    {'en': 'Open your authenticator app and enter the 6-digit code for '
                                'depressedyoungmanblog.',
                          'fr': 'Ouvre ton application d\'authentification et saisis le code à '
                                '6 chiffres pour depressedyoungmanblog.'},
    'auth.totp.verify':  {'en': 'Verify',          'fr': 'Vérifier'},

    # ------------------------------------------------------------ account
    'account.eyebrow':   {'en': 'Account',         'fr': 'Compte'},
    'account.password.title': {'en': 'Change your password',
                               'fr': 'Changer ton mot de passe'},
    'account.password.lede': {'en': 'You will stay signed in on this device and be signed '
                                    'out everywhere else.',
                              'fr': 'Tu resteras connecté sur cet appareil et seras '
                                    'déconnecté partout ailleurs.'},
    'account.password.forced': {'en': 'This account was created with a generated password. '
                                      'Choose your own before going any further — nothing '
                                      'else is reachable until you do.',
                                'fr': 'Ce compte a été créé avec un mot de passe généré. '
                                      'Choisis le tien avant d\'aller plus loin — rien '
                                      'd\'autre n\'est accessible tant que ce n\'est pas fait.'},
    'account.password.current': {'en': 'Current password', 'fr': 'Mot de passe actuel'},
    'account.password.new': {'en': 'New password',        'fr': 'Nouveau mot de passe'},
    'account.password.confirm': {'en': 'Confirm new password',
                                 'fr': 'Confirmer le nouveau mot de passe'},
    'account.password.hint': {'en': 'At least 12 characters.',
                              'fr': 'Au moins 12 caractères.'},
    'account.password.submit': {'en': 'Change password', 'fr': 'Changer le mot de passe'},
    'account.password.link': {'en': 'Change password',   'fr': 'Changer le mot de passe'},

    # --------------------------------------------------------------- chat
    'chat.title':        {'en': 'Chat',            'fr': 'Chat'},
    'chat.body':         {'en': 'Messages here are encrypted before they are stored.',
                          'fr': 'Les messages sont chiffrés avant d\'être enregistrés.'},
    'chat.placeholder':  {'en': 'Type your message…',
                          'fr': 'Écris ton message…'},
    'chat.send':         {'en': 'Send',            'fr': 'Envoyer'},
    'chat.empty':        {'en': 'No messages yet.','fr': 'Aucun message pour l\'instant.'},

    # ------------------------------------------------------------- donate
    'donate.eyebrow':    {'en': 'Support',         'fr': 'Soutien'},
    'donate.title':      {'en': 'Keep this space alive',
                          'fr': 'Garder cet espace en vie'},
    'donate.body':       {'en': 'Trocador lets you swap any cryptocurrency for Monero (XMR) and '
                                'send it directly — no account, no trace.',
                          'fr': 'Trocador permet d\'échanger n\'importe quelle cryptomonnaie '
                                'contre du Monero (XMR) et de l\'envoyer directement — sans '
                                'compte, sans trace.'},
    'donate.top':        {'en': 'Top supporters this month',
                          'fr': 'Principaux soutiens ce mois-ci'},
    'donate.none':       {'en': 'No donations yet this month. You could be the first.',
                          'fr': 'Aucun don ce mois-ci. Tu pourrais être le premier.'},
    'donate.widget.load': {'en': 'Load the Trocador widget',
                           'fr': 'Charger le widget Trocador'},
    'donate.widget.hide': {'en': 'Hide the widget',
                           'fr': 'Masquer le widget'},
    'donate.widget.newtab': {'en': 'Open it in a new tab instead',
                             'fr': 'L\'ouvrir plutôt dans un nouvel onglet'},
    'donate.widget.warning': {'en': 'The swap widget is hosted by trocador.app. Loading it lets '
                                    'that third party see your IP address and browser. It stays '
                                    'unloaded until you ask for it.',
                              'fr': 'Le widget d\'échange est hébergé par trocador.app. Le charger '
                                    'permet à ce tiers de voir ton adresse IP et ton navigateur. '
                                    'Il reste inactif tant que tu ne le demandes pas.'},
    'donate.crypto.title': {'en': 'Donate with crypto',
                            'fr': 'Faire un don en cryptomonnaie'},
    'donate.crypto.body': {'en': 'Choose your preferred cryptocurrency and scan the QR code, or '
                                 'tap an address to copy it.',
                           'fr': 'Choisis ta cryptomonnaie et scanne le QR code, ou touche une '
                                 'adresse pour la copier.'},


    # ------------------------------------------------- private (chat, profil)
    'chat.heading':      {'en': 'Chat with the admin',
                          'fr': 'Discuter avec l\'administrateur'},
    'chat.sub':          {'en': 'Send a private message to the blog administrator',
                          'fr': 'Envoie un message privé à l\'administrateur du blog'},
    'chat.attach':       {'en': 'Attach a file', 'fr': 'Joindre un fichier'},

    'profile.articles':  {'en': 'Articles',       'fr': 'Articles'},
    'profile.comments':  {'en': 'Comments',       'fr': 'Commentaires'},
    'profile.level':     {'en': 'Level',          'fr': 'Niveau'},
    'profile.likes':     {'en': 'Likes received', 'fr': 'J\'aime reçus'},
    'profile.badges_empty': {'en': 'No badges earned yet',
                             'fr': 'Aucun badge obtenu pour l\'instant'},
    'profile.picture_alt': {'en': 'Profile picture', 'fr': 'Photo de profil'},
    'profile.mine':      {'en': 'My profile',     'fr': 'Mon profil'},
    'profile.other':     {'en': 'Profile',        'fr': 'Profil'},
    'profile.recent_articles': {'en': 'Recent articles', 'fr': 'Articles récents'},
    'profile.recent_comments': {'en': 'Recent comments', 'fr': 'Commentaires récents'},

    'edit.title':        {'en': 'Edit profile',   'fr': 'Modifier le profil'},
    'edit.sub':          {'en': 'Update your account information',
                          'fr': 'Mets à jour les informations de ton compte'},
    'edit.username':     {'en': 'Username (for login only)',
                          'fr': 'Nom d\'utilisateur (pour la connexion uniquement)'},
    'edit.username_ph':  {'en': 'Your username', 'fr': 'Ton nom d\'utilisateur'},
    'edit.picture':      {'en': 'Profile picture', 'fr': 'Photo de profil'},
    'edit.picture_current': {'en': 'Current picture', 'fr': 'Photo actuelle'},
    'edit.formats':      {'en': 'Allowed formats: JPG, JPEG, PNG, GIF',
                          'fr': 'Formats acceptés : JPG, JPEG, PNG, GIF'},

    'totp.section':      {'en': 'Two-factor authentication',
                          'fr': 'Authentification à deux facteurs'},
    'totp.enable':       {'en': 'Enable two-factor authentication',
                          'fr': 'Activer l\'authentification à deux facteurs'},
    'totp.disable':      {'en': 'Disable two-factor authentication',
                          'fr': 'Désactiver l\'authentification à deux facteurs'},
    'totp.step_open':    {'en': 'Open your authenticator app.',
                          'fr': 'Ouvre ton application d\'authentification.'},
    'totp.step_scan':    {'en': 'Scan the QR code or enter the key above.',
                          'fr': 'Scanne le QR code ou saisis la clé ci-dessus.'},
    'totp.step_type':    {'en': 'Type the 6-digit code shown in the app below.',
                          'fr': 'Saisis ci-dessous le code à 6 chiffres affiché dans l\'application.'},
    'totp.manual':       {'en': 'Or enter this key manually:',
                          'fr': 'Ou saisis cette clé manuellement :'},
    'totp.qr_alt':       {'en': 'TOTP QR code', 'fr': 'QR code TOTP'},
    'totp.current_password': {'en': 'Current password', 'fr': 'Mot de passe actuel'},
    'totp.enable_short': {'en': 'Enable 2FA',      'fr': 'Activer la 2FA'},
    'totp.setup_sub':    {'en': 'Scan the QR code with an authenticator app (Google '
                                'Authenticator, Aegis, etc.) then enter the 6-digit code to '
                                'confirm.',
                          'fr': 'Scanne le QR code avec une application d\'authentification '
                                '(Google Authenticator, Aegis, etc.) puis saisis le code à '
                                '6 chiffres pour confirmer.'},

    # --------------------------------------------------------------- misc
    'misc.notifications.title': {'en': 'Notifications', 'fr': 'Notifications'},
    'misc.notifications.empty_title': {'en': 'No notifications',
                                       'fr': 'Aucune notification'},
    'misc.notifications.empty_body': {'en': 'You don\'t have any notifications yet.',
                                      'fr': 'Tu n\'as encore aucune notification.'},
    'misc.notifications.mark_read': {'en': 'Read', 'fr': 'Lu'},
    'misc.notifications.view': {'en': 'View', 'fr': 'Voir'},
    'misc.notifications.mark_all': {'en': 'Mark all as read',
                                    'fr': 'Tout marquer comme lu'},
    'misc.profile.member_since': {'en': 'Member since', 'fr': 'Membre depuis'},
    'misc.profile.edit': {'en': 'Edit profile',    'fr': 'Modifier le profil'},
    'misc.save':         {'en': 'Save',            'fr': 'Enregistrer'},
    'misc.cancel':       {'en': 'Cancel',          'fr': 'Annuler'},
    'misc.back':         {'en': 'Back',            'fr': 'Retour'},
}


# Le texte de la page « À propos » est long et propre a l'auteur : il est repris
# tel quel du gabarit d'origine plutot que reecrit ici.
DEFAULTS['about.body']['en'] = (
    "Hi, welcome to depressedyoungmanblog.\n\n"
    "This is just a personal blog. I made it mostly to write things that are on my mind and "
    "sometimes share them with whoever ends up here. Writing helps me clear my head, and it's "
    "also a way to talk with people online. I'm a teenager from France, currently studying.\n\n"
    "This blog doesn't really have one specific topic. It's mostly about whatever I feel like "
    "writing about. Sometimes it might be random thoughts, sometimes things about the internet, "
    "privacy, or just things I find interesting.\n\n"
    "I'm not an expert in anything and I'm not trying to be one. This blog is simply a place to "
    "share ideas and thoughts.\n\n"
    "I believe privacy is a fundamental right, and it's something people shouldn't have to give "
    "up just to use the internet.\n\n"
    "[b]Why Tor for this blog?[/b]\n\n"
    "First, because I believe privacy is important. Second, because Tor itself is both disturbing "
    "and fascinating at the same time, and I wanted to add my small contribution to this space.\n\n"
    "[b]A quick note[/b]\n\n"
    "Misogyny, racism, or homophobia are not welcome here. The values that matter most to me are "
    "respect and open-mindedness. Everyone has different opinions and perspectives, and that's "
    "part of what makes discussions interesting.\n\n"
    "There isn't really a big goal behind this blog. It's just a place to write, think, and "
    "sometimes share. If you're here reading this, thanks for stopping by."
)
DEFAULTS['about.body']['fr'] = (
    "Salut, bienvenue sur depressedyoungmanblog.\n\n"
    "C'est simplement un blog personnel. Je l'ai fait surtout pour écrire ce que j'ai en tête et "
    "parfois le partager avec ceux qui atterrissent ici. Écrire m'aide à y voir clair, et c'est "
    "aussi une façon de discuter avec des gens en ligne. Je suis un adolescent français, encore "
    "étudiant.\n\n"
    "Ce blog n'a pas vraiment de sujet précis. Il parle surtout de ce dont j'ai envie de parler. "
    "Parfois des pensées en vrac, parfois l'internet, la vie privée, ou juste des choses que je "
    "trouve intéressantes.\n\n"
    "Je ne suis expert en rien et je n'essaie pas de l'être. Ce blog est simplement un endroit "
    "pour partager des idées.\n\n"
    "Je crois que la vie privée est un droit fondamental, et que personne ne devrait avoir à y "
    "renoncer juste pour utiliser internet.\n\n"
    "[b]Pourquoi Tor pour ce blog ?[/b]\n\n"
    "D'abord parce que la vie privée compte. Ensuite parce que Tor est à la fois dérangeant et "
    "fascinant, et que je voulais apporter ma petite contribution à cet espace.\n\n"
    "[b]Une précision[/b]\n\n"
    "La misogynie, le racisme et l'homophobie ne sont pas les bienvenus ici. Ce qui compte le "
    "plus pour moi, c'est le respect et l'ouverture d'esprit. Chacun a ses opinions et ses "
    "perspectives, et c'est une partie de ce qui rend les discussions intéressantes.\n\n"
    "Il n'y a pas de grand objectif derrière ce blog. C'est juste un endroit pour écrire, "
    "réfléchir, et parfois partager. Si tu lis ces lignes, merci d'être passé."
)


# ---------------------------------------------------------------- resolution

def normalize_language(value):
    """Retourne un code de langue supporte, ou None."""
    if not value:
        return None
    code = str(value).strip().lower()[:2]
    return code if code in LANGUAGES else None


def resolve_language():
    """Langue de la requete courante.

    Priorite : ?lang= (choix explicite, memorise en session) > session >
    en-tete Accept-Language du navigateur > anglais.
    """
    chosen = normalize_language(request.args.get('lang'))
    if chosen:
        session['lang'] = chosen
        return chosen

    stored = normalize_language(session.get('lang'))
    if stored:
        return stored

    # `best_match` lit Accept-Language. C'est un en-tete que le navigateur
    # envoie de toute facon ; on ne l'enregistre nulle part.
    header = request.accept_languages.best_match(list(LANGUAGES)) if request else None
    return normalize_language(header) or DEFAULT_LANGUAGE


def current_language():
    """Langue de la requete, calculee une seule fois par requete."""
    if not hasattr(g, 'lang'):
        g.lang = resolve_language()
    return g.lang


def _overrides():
    """Textes personnalises par l'admin, charges une fois par requete."""
    if not hasattr(g, 'site_text_overrides'):
        from app import db
        from app.models import SiteText
        try:
            rows = db.session.query(
                SiteText.key, SiteText.text_en, SiteText.text_fr).all()
            g.site_text_overrides = {
                key: {'en': text_en, 'fr': text_fr}
                for key, text_en, text_fr in rows
            }
        except (OperationalError, ProgrammingError):
            # Table absente (migration pas encore appliquee) : on retombe sur
            # les valeurs par defaut plutot que de casser la page. Le rollback
            # evite de laisser la session en « pending rollback » pour le reste
            # de la requete.
            db.session.rollback()
            g.site_text_overrides = {}
    return g.site_text_overrides


def get_text(key, lang=None):
    """Texte resolu pour `key`. Voir l'ordre de resolution en tete de module."""
    lang = normalize_language(lang) or current_language()

    override = _overrides().get(key)
    if override:
        value = override.get(lang)
        if value and value.strip():
            return value

    default = DEFAULTS.get(key)
    if not default:
        return key
    return default.get(lang) or default.get(DEFAULT_LANGUAGE) or key


def render_rich(raw):
    """Texte long -> HTML : BBCode, ligne vide = paragraphe, saut simple = <br>.

    Les navigateurs envoient les sauts de ligne d'un textarea en `\r\n` : on
    normalise d'abord, sinon `\r\n\r\n` ne serait jamais reconnu comme une
    ligne vide. `parse_bbcode` echappe avant de mettre en forme ; les <br> sont
    ajoutes apres, sur du HTML deja sur.
    """
    from markupsafe import Markup
    from app.utils import parse_bbcode

    raw = (raw or '').replace('\r\n', '\n').replace('\r', '\n')
    blocks = [b.strip() for b in raw.split('\n\n') if b.strip()]
    html = ''.join(
        '<p>' + parse_bbcode(b).replace('\n', '<br>') + '</p>' for b in blocks
    )
    return Markup(html)


def get_rich_text(key, lang=None):
    """Comme `get_text`, mais rendu en HTML : BBCode + sauts de ligne."""
    return render_rich(get_text(key, lang))


MONTHS_SHORT = {
    'en': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
           'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
    'fr': ['janv.', 'févr.', 'mars', 'avr.', 'mai', 'juin',
           'juil.', 'août', 'sept.', 'oct.', 'nov.', 'déc.'],
}
MONTHS_LONG = {
    'en': ['January', 'February', 'March', 'April', 'May', 'June',
           'July', 'August', 'September', 'October', 'November', 'December'],
    'fr': ['janvier', 'février', 'mars', 'avril', 'mai', 'juin',
           'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'],
}


def format_date(value, style='short', lang=None):
    """Date localisee sans passer par `locale` ni par une bibliotheque tierce.

    `strftime('%b')` suit la locale du processus, pas celle du lecteur : sur un
    serveur en C/POSIX il renvoie toujours l'anglais. Les noms de mois sont donc
    traduits ici.

    style='short' -> « Aug 24 · 03:47 » / « 24 août · 03:47 »
    style='long'  -> « August 24, 2026 at 03:47 » / « 24 août 2026 à 03:47 »
    """
    if value is None:
        return ''
    lang = normalize_language(lang) or current_language()
    idx = value.month - 1

    if style == 'long':
        month = MONTHS_LONG.get(lang, MONTHS_LONG['en'])[idx]
        if lang == 'fr':
            return f"{value.day} {month} {value.year} à {value:%H:%M}"
        return f"{month} {value.day}, {value.year} at {value:%H:%M}"

    month = MONTHS_SHORT.get(lang, MONTHS_SHORT['en'])[idx]
    if lang == 'fr':
        return f"{value.day} {month} · {value:%H:%M}"
    return f"{month} {value.day} · {value:%H:%M}"


def grouped_defaults():
    """Cles regroupees par page, pour l'editeur de l'admin."""
    out = []
    for prefix, label in GROUPS:
        keys = sorted(k for k in DEFAULTS if k.split('.')[0] == prefix)
        if keys:
            out.append((prefix, label, keys))
    return out


# --------------------------------------------------------- validation (admin)

MAX_PLAIN = 500
MAX_RICH = 20000
EMAIL_KEYS = {'contact.email_address'}

_CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')
_EMAIL_RE = re.compile(r'^[^@\s<>"]+@[^@\s<>"]+\.[^@\s<>"]+$')


def normalize_text(value):
    """Valeur saisie -> valeur stockable, ou None (= pas de personnalisation)."""
    if value is None:
        return None
    value = str(value).replace('\r\n', '\n').replace('\r', '\n')
    value = _CONTROL_CHARS.sub('', value).strip()
    return value or None


def effective_override(key, lang, value):
    """Normalise, et renvoie None si la valeur est identique au defaut.

    Stocker une copie du defaut ferait croire a une modification et couperait
    le texte des futures corrections du code.
    """
    value = normalize_text(value)
    default = DEFAULTS.get(key, {}).get(lang)
    if value is not None and default is not None and value == default:
        return None
    return value


def validate_value(key, lang, value):
    """Message d'erreur si `value` est refusee, sinon None."""
    if not value:
        return None
    rich = key in RICH_KEYS
    limit = MAX_RICH if rich else MAX_PLAIN
    if len(value) > limit:
        return f'{lang.upper()}: too long ({len(value)} characters, maximum {limit}).'
    if key in EMAIL_KEYS and not _EMAIL_RE.match(value):
        return f'{lang.upper()}: not a valid email address.'
    if not rich and '\n' in value:
        default = DEFAULTS.get(key, {}).get(lang) or ''
        if '\n' not in default:
            return f'{lang.upper()}: must be a single line.'
    return None


# ------------------------------------------------------------ usage des cles

@functools.lru_cache(maxsize=1)
def key_usage():
    """{cle: [gabarits qui l'affichent]}, d'apres un scan des gabarits."""
    pattern = re.compile(r"\bt(?:_rich)?\(\s*['\"]([a-z0-9_.]+)['\"]")
    root = os.path.join(os.path.dirname(__file__), 'templates')
    usage = {}
    for folder, _dirs, files in os.walk(root):
        for name in files:
            if not name.endswith('.html'):
                continue
            with open(os.path.join(folder, name), encoding='utf-8') as fh:
                found = set(pattern.findall(fh.read()))
            for key in found:
                usage.setdefault(key, []).append(name)
    return {key: sorted(names) for key, names in usage.items()}


def orphan_keys(overrides):
    """Cles presentes en base mais retirees de DEFAULTS."""
    return sorted(k for k in overrides if k not in DEFAULTS)


# ------------------------------------------------- ecriture, historique, audit

REVISIONS_KEPT = 30


def _hash_pair(en, fr):
    raw = ((en or '') + '\x00' + (fr or '')).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()[:16]


def fingerprint_values(en, fr):
    """Empreinte d'un couple (en, fr) ; '-' quand il n'y a pas de personnalisation."""
    if en is None and fr is None:
        return '-'
    return _hash_pair(en, fr)


def fingerprint(row):
    """Empreinte de la ligne SiteText (None -> '-'). Sert a detecter un conflit."""
    if row is None:
        return '-'
    return fingerprint_values(row.text_en, row.text_fr)


def apply_change(key, en, fr, action, user_id):
    """Ecrit l'etat (en, fr) pour `key`. True si quelque chose a change.

    `en` / `fr` sont deja passes par `effective_override`. Deux None = retour
    au defaut (la ligne est supprimee). Ne commit pas : l'appelant commit une
    seule fois. Aucune IP ni User-Agent n'est enregistre.
    """
    from app import db
    from app.models import SiteText, SiteTextRevision

    row = SiteText.query.filter_by(key=key).first()

    if en is None and fr is None:
        if row is None:
            return False
        db.session.delete(row)
    else:
        if row is None:
            row = SiteText(key=key)
            db.session.add(row)
        elif row.text_en == en and row.text_fr == fr:
            return False
        row.text_en = en
        row.text_fr = fr
        row.updated_by_id = user_id

    db.session.add(SiteTextRevision(
        key=key, text_en=en, text_fr=fr, action=action, changed_by_id=user_id))
    db.session.flush()

    # Retention : on garde les plus recentes, on supprime le reste.
    stale = (db.session.query(SiteTextRevision.id)
             .filter_by(key=key)
             .order_by(SiteTextRevision.id.desc())
             .offset(REVISIONS_KEPT).all())
    if stale:
        SiteTextRevision.query.filter(
            SiteTextRevision.id.in_([r.id for r in stale])
        ).delete(synchronize_session=False)
    return True
