from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, DateTimeField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, URL, Optional, NumberRange, Email
from app.models import User
from flask_ckeditor import CKEditorField

# Refus des mots de passe les plus evidents. Liste volontairement courte : elle
# bloque les choix reflexes sans donner l'illusion d'un vrai controle de force.
_COMMON_PASSWORDS = {
    'password', 'password123', 'motdepasse', 'azertyuiop', 'qwertyuiop',
    '123456789012', 'administrator', 'letmein12345', 'iloveyou1234',
    'welcome12345', 'changeme1234', 'passwordpassword',
}

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    # 12 caracteres minimum : un compte de ce blog protege une conversation
    # privee avec l'administration, pas seulement des commentaires.
    password = PasswordField('Password', validators=[DataRequired(), Length(min=12, max=256)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_password(self, password):
        value = password.data or ''
        if value.lower() in _COMMON_PASSWORDS:
            raise ValidationError('This password is too common. Choose another one.')
        if self.username.data and self.username.data.lower() in value.lower():
            raise ValidationError('The password must not contain your username.')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = CKEditorField('Content', validators=[DataRequired()])
    scheduled_date = DateTimeField('Scheduled Date', format='%Y-%m-%d %H:%M:%S', validators=[Optional()])
    is_published = BooleanField('Publish Now')
    submit = SubmitField('Submit')

class CommentForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post Comment')

class ReplyForm(FlaskForm):
    content = TextAreaField('Reply', validators=[DataRequired()])
    submit = SubmitField('Post Reply')

class EmptyForm(FlaskForm):
    submit = SubmitField('Submit')

class SiteTextImportForm(FlaskForm):
    file = FileField('JSON file', validators=[FileRequired(), FileAllowed(['json'])])
    submit = SubmitField('Import')

class BannerForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=100)])
    content = TextAreaField('Content', validators=[DataRequired()])
    image_url = StringField('Image URL', validators=[DataRequired(), URL()])
    link_url = StringField('Link URL', validators=[DataRequired(), URL()])
    position = SelectField('Position', choices=[('header', 'Header'), ('sidebar', 'Sidebar'), ('footer', 'Footer')], validators=[DataRequired()])
    is_active = BooleanField('Active')
    submit = SubmitField('Save Banner')

class PageForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=100)])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Save')

class StaticPageForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    slug = StringField('Slug', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Save Changes')

class ContactForm(FlaskForm):
    name = StringField('Your Name', validators=[DataRequired()])
    email = StringField('Your Email', validators=[DataRequired(), Email()])  # ✅ Email est maintenant défini
    message = TextAreaField('Your Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')

class ProfileEditForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    profile_picture = FileField('Profile Picture', validators=[FileAllowed(['jpg', 'png', 'gif', 'jpeg'], 'Images only!')])
    submit = SubmitField('Update Profile')
    
    def __init__(self, original_username, *args, **kwargs):
        super(ProfileEditForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
    
    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user:
                raise ValidationError('That username is already taken. Please choose a different one.')


class ChangePasswordForm(FlaskForm):
    """Changement de mot de passe : l'actuel est exige pour eviter qu'une
    session laissee ouverte suffise a verrouiller le compte."""
    current_password = PasswordField('Current password', validators=[DataRequired()])
    new_password = PasswordField(
        'New password', validators=[DataRequired(), Length(min=12, max=256)])
    confirm_password = PasswordField(
        'Confirm new password',
        validators=[DataRequired(), EqualTo('new_password', message='The two entries differ.')])
    submit = SubmitField('Change password')

    def validate_new_password(self, new_password):
        value = new_password.data or ''
        if value.lower() in _COMMON_PASSWORDS:
            raise ValidationError('This password is too common. Choose another one.')
        if value == (self.current_password.data or ''):
            raise ValidationError('The new password must be different from the current one.')


class TOTPSetupForm(FlaskForm):
    """Confirm the first TOTP code after scanning the QR to activate 2FA."""
    code = StringField('6-digit code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Enable 2FA')


class TOTPDisableForm(FlaskForm):
    """Confirm current password + a valid TOTP code to disable 2FA."""
    password = PasswordField('Current password', validators=[DataRequired()])
    code = StringField('6-digit code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Disable 2FA')


class TOTPVerifyForm(FlaskForm):
    """Second-step form shown at login when 2FA is enabled."""
    code = StringField('6-digit code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')
