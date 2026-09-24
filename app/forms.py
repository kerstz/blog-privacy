from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, DateTimeField, SelectField, HiddenField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, URL, Optional, Email, Regexp
from app.models import User
from flask import current_app
from itsdangerous import URLSafeTimedSerializer, BadData
import time

# Usernames are shown in many places (admin panel, Telegram, chat): restrict
# them to a safe charset so they can never carry markup or script payloads.
USERNAME_VALIDATORS = [
    DataRequired(), Length(min=2, max=20),
    Regexp(r'^[A-Za-z0-9_.-]+$', message='Letters, digits, "_", "." and "-" only.'),
]
# bcrypt only uses the first 72 bytes of a password.
PASSWORD_MAX = 72
TOTP_CODE_VALIDATORS = [DataRequired(), Length(min=6, max=6), Regexp(r'^\d{6}$', message='6 digits.')]
# 6-digit TOTP code or a recovery code (XXXXX-XXXXX)
SECOND_FACTOR_VALIDATORS = [
    DataRequired(), Length(min=6, max=11),
    Regexp(r'^(\d{6}|[A-Za-z0-9]{5}-?[A-Za-z0-9]{5})$', message='6-digit code or recovery code.'),
]
NEW_PASSWORD_VALIDATORS = [
    DataRequired(),
    Length(min=12, max=PASSWORD_MAX, message='Password must be 12 to 72 characters long.'),
]


# ---------------------------------------------------------------- anti-spam
def _antispam_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'], salt='antispam-form')


def _new_antispam_token():
    return _antispam_serializer().dumps(int(time.time()))


class AntiSpamMixin:
    """No-JS, no third-party anti-spam for public forms:
    - `website` is a honeypot: hidden with CSS, humans leave it empty;
    - `form_ts` is a signed render time: the form must be at least
      ANTISPAM_MIN_SECONDS old (bots post instantly) and at most one day old.
    Disabled when app.config['ANTISPAM_ENABLED'] is False."""
    website = StringField('Leave this field empty', render_kw={'autocomplete': 'off', 'tabindex': '-1'})
    form_ts = HiddenField(default=_new_antispam_token)

    def validate_website(self, field):
        if current_app.config.get('ANTISPAM_ENABLED', True) and (field.data or '').strip():
            raise ValidationError('Spam detected.')

    def validate_form_ts(self, field):
        if not current_app.config.get('ANTISPAM_ENABLED', True):
            return
        try:
            issued = _antispam_serializer().loads(field.data or '', max_age=86400)
        except BadData:
            raise ValidationError('This form expired, please reload the page.')
        if time.time() - int(issued) < current_app.config.get('ANTISPAM_MIN_SECONDS', 3):
            raise ValidationError('Please wait a few seconds before submitting.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=PASSWORD_MAX)])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(AntiSpamMixin, FlaskForm):
    username = StringField('Username', validators=USERNAME_VALIDATORS)
    password = PasswordField('Password', validators=NEW_PASSWORD_VALIDATORS)
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Content', validators=[DataRequired()])
    category = StringField('Category', validators=[Optional(), Length(max=60)])
    tags = StringField('Tags (comma separated)', validators=[Optional(), Length(max=300)])
    scheduled_date = DateTimeField('Scheduled Date', format='%Y-%m-%d %H:%M:%S', validators=[Optional()])
    is_published = BooleanField('Publish Now')
    submit = SubmitField('Submit')

class CommentForm(AntiSpamMixin, FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired(), Length(max=5000)])
    submit = SubmitField('Post Comment')

class ReplyForm(FlaskForm):
    content = TextAreaField('Reply', validators=[DataRequired(), Length(max=5000)])
    submit = SubmitField('Post Reply')

class EmptyForm(FlaskForm):
    submit = SubmitField('Submit')

class BannerForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=100)])
    content = TextAreaField('Content', validators=[DataRequired()])
    # URL() alone accepts "javascript://..." : force http(s)
    image_url = StringField('Image URL', validators=[DataRequired(), URL(), Length(max=255), Regexp(r'^https?://', message='http(s) URL only.')])
    link_url = StringField('Link URL', validators=[DataRequired(), URL(), Length(max=255), Regexp(r'^https?://', message='http(s) URL only.')])
    position = SelectField('Position', choices=[('header', 'Header'), ('sidebar', 'Sidebar'), ('footer', 'Footer')], validators=[DataRequired()])
    is_active = BooleanField('Active')
    submit = SubmitField('Save Banner')

class PageForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=100)])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Save')

class StaticPageForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    slug = StringField('Slug', validators=[Optional(), Length(max=100),
                                           Regexp(r'^[a-z0-9]+(?:-[a-z0-9]+)*$', message='Lowercase letters, digits and dashes only.')])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Save Changes')

class ContactForm(AntiSpamMixin, FlaskForm):
    name = StringField('Your Name', validators=[DataRequired(), Length(max=100)])
    email = StringField('Your Email', validators=[DataRequired(), Email(), Length(max=120)])
    message = TextAreaField('Your Message', validators=[DataRequired(), Length(max=5000)])
    submit = SubmitField('Send Message')

class ProfileEditForm(FlaskForm):
    username = StringField('Username', validators=USERNAME_VALIDATORS)
    profile_picture = FileField('Profile Picture', validators=[FileAllowed(['jpg', 'png', 'gif', 'jpeg', 'webp'], 'Images only!')])
    submit = SubmitField('Update Profile')
    
    def __init__(self, original_username, *args, **kwargs):
        super(ProfileEditForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
    
    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user:
                raise ValidationError('That username is already taken. Please choose a different one.')


class TOTPSetupForm(FlaskForm):
    """Confirm the first TOTP code after scanning the QR to activate 2FA."""
    code = StringField('6-digit code', validators=TOTP_CODE_VALIDATORS)
    submit = SubmitField('Enable 2FA')


class TOTPDisableForm(FlaskForm):
    """Confirm current password + a valid TOTP (or recovery) code to disable 2FA."""
    password = PasswordField('Current password', validators=[DataRequired(), Length(max=PASSWORD_MAX)])
    code = StringField('6-digit code or recovery code', validators=SECOND_FACTOR_VALIDATORS)
    submit = SubmitField('Disable 2FA')


class TOTPVerifyForm(FlaskForm):
    """Second-step form shown at login when 2FA is enabled."""
    code = StringField('6-digit code or recovery code', validators=SECOND_FACTOR_VALIDATORS)
    submit = SubmitField('Verify')


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current password', validators=[DataRequired(), Length(max=PASSWORD_MAX)])
    new_password = PasswordField('New password', validators=NEW_PASSWORD_VALIDATORS)
    confirm_password = PasswordField('Confirm new password', validators=[DataRequired(), EqualTo('new_password', message='Passwords do not match.')])
    submit = SubmitField('Change password')


class ReauthForm(FlaskForm):
    """Re-enter the password (and the 2FA code when enabled) before a sensitive action."""
    password = PasswordField('Current password', validators=[DataRequired(), Length(max=PASSWORD_MAX)])
    code = StringField('2FA code or recovery code (if 2FA is enabled)', validators=[
        Optional(), Length(min=6, max=11),
        Regexp(r'^(\d{6}|[A-Za-z0-9]{5}-?[A-Za-z0-9]{5})$', message='6-digit code or recovery code.'),
    ])
    submit = SubmitField('Confirm')


class DeleteAccountForm(ReauthForm):
    confirm = StringField('Type DELETE to confirm', validators=[DataRequired(), Regexp(r'^DELETE$', message='Type DELETE in capital letters.')])
    submit = SubmitField('Delete my account')
