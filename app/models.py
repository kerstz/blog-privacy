from datetime import datetime
from flask_login import UserMixin

from . import db

# Many-to-many link between posts and tags
post_tags = db.Table(
    'post_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True),
)


class Tag(db.Model):
    __tablename__ = 'tag'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True, nullable=False)
    slug = db.Column(db.String(50), unique=True, nullable=False, index=True)

    def __repr__(self):
        return f"Tag('{self.name}')"


# Post Model
class Post(db.Model):
    __tablename__ = 'post'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    scheduled_date = db.Column(db.DateTime, nullable=True)
    is_published = db.Column(db.Boolean, default=False)
    is_draft = db.Column(db.Boolean, default=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    likes_count = db.Column(db.Integer, default=0)
    views_count = db.Column(db.Integer, default=0)
    category = db.Column(db.String(60), nullable=True, index=True)

    # Relationships
    revisions = db.relationship('Revision', back_populates='post', lazy=True)
    author = db.relationship('User', back_populates='posts')
    comments = db.relationship('Comment', back_populates='post', lazy=True)
    likes = db.relationship('Like', back_populates='post', lazy=True)
    tags = db.relationship('Tag', secondary=post_tags, lazy='subquery',
                           backref=db.backref('posts', lazy=True))

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"


# Comment Model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False, default='[deleted]')
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    deleted = db.Column(db.Boolean, default=False)
    likes_count = db.Column(db.Integer, default=0)
    # NULL = ligne ancienne : `content` est du HTML stocke tel quel (assaini a
    # l'affichage). 'bbcode' = texte brut + BBCode, converti en HTML (echappe)
    # au rendu. Voir app/utils.py et le filtre `comment_html`.
    content_format = db.Column(db.String(10), nullable=True)

    # Relationships
    post = db.relationship('Post', back_populates='comments')
    author = db.relationship('User', back_populates='comments')
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy=True)
    likes = db.relationship('Like', back_populates='comment', lazy=True)

    def __repr__(self):
        return f"Comment('{self.content}', '{self.date_posted}')"


# Revision Model
class Revision(db.Model):
    __tablename__ = 'revision'

    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_modified = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    version = db.Column(db.Integer, nullable=False)

    # Relationship back to Post
    post = db.relationship('Post', back_populates='revisions')

    def __repr__(self):
        return f"Revision('{self.version}', '{self.date_modified}')"


# Banner Model
class Banner(db.Model):
    __tablename__ = 'banner'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    link_url = db.Column(db.String(255), nullable=False)
    position = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"Banner('{self.title}', '{self.position}')"


# StaticPage Model
class StaticPage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), nullable=False, unique=True)
    content = db.Column(db.Text, nullable=False)
    date_modified = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"StaticPage('{self.title}', '{self.slug}')"


# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    level = db.Column(db.Integer, default=1)
    experience_points = db.Column(db.Integer, default=0)
    badges = db.Column(db.Text, default='')  # JSON string of badges
    profile_picture = db.Column(db.String(255), nullable=True)  # Path to profile picture
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    # Secret TOTP chiffre au repos (Fernet, voir encryption.py). Une ancienne
    # valeur en clair reste lisible et est rechiffree a la prochaine ecriture.
    totp_secret = db.Column(db.String(255), nullable=True)
    # Dernier pas TOTP accepte : un code deja utilise ne peut pas etre rejoue.
    totp_last_counter = db.Column(db.Integer, nullable=True)
    # SHA-256 hashes of the unused 2FA recovery codes (JSON list)
    recovery_codes = db.Column(db.Text, nullable=True)
    # Bumped on password change / "log out everywhere": invalidates every
    # existing session and remember-me cookie of this user.
    session_version = db.Column(db.Integer, nullable=False, default=0, server_default='0')

    # Pose a la creation d'un compte dont le mot de passe a ete genere par un
    # script : tant qu'il vaut True, toute navigation est renvoyee vers le
    # changement de mot de passe.
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)

    # Bannissement. `is_banned` coupe l'acces des la session suivante ET la
    # session en cours (voir le before_request dans routes.py).
    is_banned = db.Column(db.Boolean, default=False, nullable=False)
    banned_at = db.Column(db.DateTime, nullable=True)
    ban_reason = db.Column(db.String(255), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    posts = db.relationship('Post', back_populates='author', lazy=True)
    comments = db.relationship('Comment', back_populates='author', lazy=True)
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', back_populates='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', back_populates='receiver', lazy=True)
    likes_given = db.relationship('Like', foreign_keys='Like.user_id', back_populates='user', lazy=True)
    notifications = db.relationship('Notification', back_populates='user', lazy=True)

    def get_id(self):
        # Flask-Login stores this in the session / remember cookie
        return f"{self.id}:{self.session_version or 0}"

    def rotate_session_token(self):
        """Invalide toutes les sessions et cookies "remember" deja emis."""
        self.session_version = (self.session_version or 0) + 1

    def get_badges(self):
        """Returns the user's badge list"""
        import json
        try:
            return json.loads(self.badges) if self.badges else []
        except (ValueError, TypeError):
            return []

    def add_badge(self, badge_name):
        """Adds a badge to the user"""
        import json
        badges = self.get_badges()
        if badge_name not in badges:
            badges.append(badge_name)
            self.badges = json.dumps(badges)
            return True
        return False

    def add_experience(self, points):
        """Adds experience points and updates level"""
        self.experience_points += points
        # Level calculation based on experience (100 points per level)
        new_level = (self.experience_points // 100) + 1
        if new_level > self.level:
            self.level = new_level
            return True  # Level increased
        return False

    def unread_notifications_count(self):
        """Returns the number of unread notifications"""
        return len([n for n in self.notifications if not n.is_read])

    def __repr__(self):
        return f"User('{self.username}')"


# Message Model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    file_path = db.Column(db.String(255), nullable=True)  # Path to attached file
    file_type = db.Column(db.String(50), nullable=True)  # File type (image, video, etc.)
    is_encrypted = db.Column(db.Boolean, default=True)  # Indicates if message is encrypted

    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], back_populates='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], back_populates='received_messages')

    def get_decrypted_content(self):
        """Returns the decrypted message content"""
        if self.is_encrypted:
            from app.encryption import message_encryption
            return message_encryption.decrypt_message(self.content)
        return self.content

    def set_encrypted_content(self, content):
        """Encrypts and sets the message content"""
        from app.encryption import message_encryption
        self.content = message_encryption.encrypt_message(content)
        self.is_encrypted = True

    def __repr__(self):
        return f"Message('{self.sender_id}', '{self.receiver_id}', '{self.timestamp}')"


# Donor Model
class Donor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date_donated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"Donor('{self.name}', '{self.amount}')"


# Like Model
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', back_populates='likes_given')
    post = db.relationship('Post', back_populates='likes')
    comment = db.relationship('Comment', back_populates='likes')

    # Unique constraint to avoid duplicates
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_post_like'),
                     db.UniqueConstraint('user_id', 'comment_id', name='unique_comment_like'))

    def __repr__(self):
        return f"Like('{self.user_id}', '{self.post_id or self.comment_id}')"


# Notification Model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # 'comment', 'reply', 'like', 'badge'
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    related_post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
    related_comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)

    # Relationships
    user = db.relationship('User', back_populates='notifications')
    related_post = db.relationship('Post')
    related_comment = db.relationship('Comment')

    def __repr__(self):
        return f"Notification('{self.type}', '{self.user_id}', '{self.is_read}')"


# Badge Model
class Badge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    icon = db.Column(db.String(100), nullable=False)  # Font Awesome icon name
    color = db.Column(db.String(20), nullable=False)  # Hex color
    condition = db.Column(db.String(200), nullable=False)  # Condition to obtain badge
    points_reward = db.Column(db.Integer, default=0)  # Experience points reward

    def __repr__(self):
        return f"Badge('{self.name}')"


class BlockedImageHash(db.Model):
    """Empreinte d'une image dont le televersement doit etre refuse.

    Alimentee par l'administrateur. Le site n'en produit aucune de lui-meme :
    les listes de reference (NCMEC, PhotoDNA, IWF) ne sont pas publiques et
    supposent un accord avec l'organisme qui les maintient.
    """
    __tablename__ = 'blocked_image_hash'

    id = db.Column(db.Integer, primary_key=True)
    # SHA-256 du fichier d'origine : correspondance exacte.
    sha256 = db.Column(db.String(64), nullable=True, index=True)
    # dHash 64 bits en hexadecimal : survit au ré-encodage.
    dhash = db.Column(db.String(16), nullable=True, index=True)
    label = db.Column(db.String(120), nullable=True)   # d'ou vient l'entree
    added_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"BlockedImageHash('{self.label or self.sha256 or self.dhash}')"


class BlockedUploadEvent(db.Model):
    """Trace d'un televersement refuse.

    Ne contient jamais l'image : seulement son empreinte, l'auteur et la date.
    Le fichier lui-meme part en quarantaine hors de la racine web.
    """
    __tablename__ = 'blocked_upload_event'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    matched_hash_id = db.Column(db.Integer, db.ForeignKey('blocked_image_hash.id'), nullable=True)
    distance = db.Column(db.Integer, nullable=True)   # distance de Hamming
    sha256 = db.Column(db.String(64), nullable=True)
    quarantine_name = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User')
    matched_hash = db.relationship('BlockedImageHash')

    def __repr__(self):
        return f"BlockedUploadEvent('{self.user_id}', '{self.created_at}')"


class SiteText(db.Model):
    """Un texte fixe du site, dans les deux langues.

    Ne contient que ce que l'administrateur a reellement modifie : les valeurs
    par defaut vivent dans app/site_text.py. Une colonne vide signifie
    « garder le defaut », pas « texte vide ».
    """
    __tablename__ = 'site_text'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False, index=True)
    text_en = db.Column(db.Text, nullable=True)
    text_fr = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        return f"SiteText('{self.key}')"


class SiteTextRevision(db.Model):
    """Historique des modifications des textes du site (pas d'IP, pas d'UA).

    `text_en` / `text_fr` : etat APRES le changement ; deux None = defaut.
    """
    __tablename__ = 'site_text_revision'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), nullable=False, index=True)
    text_en = db.Column(db.Text, nullable=True)
    text_fr = db.Column(db.Text, nullable=True)
    action = db.Column(db.String(16), nullable=False)  # save | reset | revert | import
    changed_by_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'),
                              nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    changed_by = db.relationship('User')

    def __repr__(self):
        return f"SiteTextRevision('{self.key}', '{self.action}')"


# GDPR: contact messages hold personal data (name, optional email); the
# `flask purge-contact` command deletes the ones older than this many days.
CONTACT_RETENTION_DAYS = 90


class ContactMessage(db.Model):
    __tablename__ = 'contact_message'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    # Optional on the form: stored as '' when the visitor gives none.
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"ContactMessage('{self.name}', '{self.timestamp}')"
