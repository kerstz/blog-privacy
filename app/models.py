from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email

from . import db

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

    # Relationships
    revisions = db.relationship('Revision', back_populates='post', lazy=True)
    author = db.relationship('User', back_populates='posts')
    comments = db.relationship('Comment', back_populates='post', lazy=True)
    likes = db.relationship('Like', back_populates='post', lazy=True)

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
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    posts = db.relationship('Post', back_populates='author', lazy=True)
    comments = db.relationship('Comment', back_populates='author', lazy=True)
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', back_populates='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', back_populates='receiver', lazy=True)
    likes_given = db.relationship('Like', foreign_keys='Like.user_id', back_populates='user', lazy=True)
    notifications = db.relationship('Notification', back_populates='user', lazy=True)

    def get_badges(self):
        """Returns the user's badge list"""
        import json
        try:
            return json.loads(self.badges) if self.badges else []
        except:
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
