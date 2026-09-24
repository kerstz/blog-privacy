"""Web routes (public pages, auth, chat, admin panel) and SocketIO handlers."""
from flask import render_template, url_for, flash, redirect, request, abort, send_from_directory, session
from flask_login import login_user, current_user, logout_user, login_required
from app import app, db, bcrypt, socketio
from app.forms import LoginForm, RegistrationForm, PostForm, CommentForm, EmptyForm, BannerForm, StaticPageForm, ContactForm, ProfileEditForm, TOTPSetupForm, TOTPDisableForm, TOTPVerifyForm
from app.models import User, Post, Comment, Revision, Banner, StaticPage, Message, Donor, Like, Notification, ContactMessage
from app.utils import rate_limit, hit_rate_limit
from datetime import datetime, timedelta
from flask_socketio import emit
from werkzeug.utils import secure_filename
import re
import os
import base64
import time
import pyotp
import io
from flask_socketio import join_room, disconnect
from app import mobile_api  # noqa: F401  (registers the /api/admin/mobile routes)
from app.services import (
    CHAT_ALLOWED_EXTENSIONS,
    IMAGE_EXTENSIONS,
    MAX_UPLOAD_BYTES,
    PROFILE_ALLOWED_EXTENSIONS,
    UPLOAD_FILE_ALLOWED_EXTENSIONS,
    _action_rate_limited,
    _check_user_password,
    _delete_post_and_children,
    _delete_user_and_data,
    _file_ext,
    _get_admin_user_id,
    _notify_admins_new_message,
    _notify_user,
    _remove_upload_file,
    _start_fresh_session,
    _store_upload,
    _user_conversation_query,
    _user_room,
    _validate_uploaded_file,
    _verify_totp_once,
    _visible_posts_query,
    admin_required,
    check_and_award_badges,
    create_default_badges,
    publish_mobile_event,
    serialize_chat_message,
)
from app.telegram_bot import (
    ensure_telegram_poller_started,
    notify_admin_telegram_new_message,
    telegram_fetch_updates,
    telegram_is_enabled,
    telegram_send_message,
    wait_for_conversation_message,
)


@app.before_request
def telegram_before_request_poll():
    # Keep Telegram bot commands responsive without JavaScript/webhooks.
    # The background poller thread handles Telegram; do not block web
    # requests with outbound HTTP calls (latency / DoS amplification).
    ensure_telegram_poller_started()
    from app.utils import publish_scheduled_posts
    publish_scheduled_posts()


# Optional .onion address, e.g. ONION_ADDRESS=abcd...xyz.onion (56 chars + .onion)
ONION_ADDRESS = (os.environ.get('ONION_ADDRESS') or '').strip().lower()
if ONION_ADDRESS and not re.fullmatch(r'[a-z2-7]{56}\.onion', ONION_ADDRESS):
    raise RuntimeError("ONION_ADDRESS must be a v3 onion address like '<56 chars>.onion'")


@app.after_request
def apply_security_headers(response):
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
    response.headers.setdefault('Cross-Origin-Resource-Policy', 'same-origin')
    if app.config.get('SESSION_COOKIE_SECURE'):
        response.headers.setdefault('Strict-Transport-Security', 'max-age=63072000; includeSubDomains')
    # Tor: advertise the .onion mirror to Tor Browser users (ONION_ADDRESS env)
    if ONION_ADDRESS and not request.host.endswith('.onion'):
        response.headers.setdefault('Onion-Location', f"http://{ONION_ADDRESS}{request.full_path.rstrip('?')}")
    # Pages for logged-in users must never be stored by shared caches.
    if current_user.is_authenticated and 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store'
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    response.headers.setdefault(
        'Content-Security-Policy',
        # No JavaScript at all, no third-party resources (Tor friendly).
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'none'; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "frame-src 'none'; "
        "object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'"
    )
    return response


# Start Telegram polling as soon as routes are imported (even without web traffic).
ensure_telegram_poller_started()


@app.route('/')
def index():
    posts = _visible_posts_query().order_by(Post.date_posted.desc()).all()
    return render_template('index.html', posts=posts)


# 🔹 About Page
@app.route('/about')
def about():
    return render_template('about.html')


# 🔹 Editor Help Page
@app.route('/editor_help')
def editor_help():
    return render_template('editor_help.html')


# 🔹 Contact Page
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        if _action_rate_limited('contact_submit', max_calls=8, window_seconds=300):
            flash('Too many contact attempts. Please wait a bit.', 'danger')
            return redirect(url_for('contact'))
        contact_msg = ContactMessage(
            name=form.name.data.strip(),
            email=form.email.data.strip(),
            message=form.message.data.strip()
        )
        db.session.add(contact_msg)
        db.session.commit()
        telegram_send_message(
            f"📬 New contact message from {contact_msg.name} ({contact_msg.email}):\n\n{contact_msg.message}"
        )
        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html', form=form)


# 🔹 View a Blog Post
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    post = _visible_posts_query().filter(Post.id == post_id).first_or_404()
    form = CommentForm()
    # Increment view counter once per session
    if request.method == 'GET':
        viewed_posts = session.get('viewed_posts', [])
        if post_id not in viewed_posts:
            post.views_count = (post.views_count or 0) + 1
            db.session.commit()
            # keep the (client-side) session cookie small
            viewed_posts = (viewed_posts + [post_id])[-100:]
            session['viewed_posts'] = viewed_posts

    if form.validate_on_submit():
        if current_user.is_authenticated:
            if _action_rate_limited('comment_submit', max_calls=12, window_seconds=300):
                flash('Too many comments in a short time. Please slow down.', 'danger')
                return redirect(url_for('post_detail', post_id=post.id))
            content = form.content.data.strip()
            if content:
                # Stored as raw BBCode; rendered + sanitized by the |comment_html filter.
                comment = Comment(content=content, post_id=post.id, author_id=current_user.id)
                db.session.add(comment)
                db.session.commit()
                
                # Add experience points for commenting
                current_user.add_experience(3)
                
                # Create notification for post author
                if post.author_id != current_user.id:
                    notification = Notification(
                        user_id=post.author_id,
                        type='comment',
                        title='New comment!',
                        message=f'Someone commented on your article "{post.title}"',
                        related_post_id=post.id,
                        related_comment_id=comment.id
                    )
                    db.session.add(notification)
                    
                    _notify_user(post.author_id, {
                        'type': 'comment',
                        'title': 'New comment!',
                        'message': f'Someone commented on your article "{post.title}"',
                    })
                
                # Check and award badges
                check_and_award_badges(current_user)
                
                db.session.commit()
                flash('Your comment has been posted!', 'success')
            else:
                flash('Comment cannot be empty.', 'danger')
        else:
            flash('You must be logged in to comment.', 'danger')
        return redirect(url_for('post_detail', post_id=post.id))

    return render_template('post_detail.html', post=post, form=form)


# 🔹 Register a User
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        if _action_rate_limited('register_submit', max_calls=5, window_seconds=3600):
            flash('Too many accounts created. Please wait.', 'danger')
            return redirect(url_for('register'))
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register', form=form)


@app.route('/login', methods=['GET', 'POST'])
@rate_limit('login', max_calls=5, window_seconds=300)
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard') if current_user.is_admin else url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        username = (form.username.data or '').strip()
        # Per-account limit (credential stuffing from many IPs)
        if hit_rate_limit(f"login_fail_user:{username.lower()}", 10, 900, record=False):
            flash('Too many failed attempts for this account. Try again later.', 'danger')
            return render_template('login.html', title='Login', form=form)
        user = User.query.filter_by(username=username).first()
        if _check_user_password(user, form.password.data):
            remember = bool(form.remember_me.data)
            _start_fresh_session()
            if user.totp_enabled:
                # Store pre-auth state in session; do NOT log in yet
                session['pre_2fa_user_id'] = user.id
                session['pre_2fa_remember'] = remember
                session['pre_2fa_started'] = time.time()
                return redirect(url_for('login_totp'))
            login_user(user, remember=remember)
            flash(f"Welcome {user.username}, you are now logged in!", "success")
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('index'))
        else:
            hit_rate_limit(f"login_fail_user:{username.lower()}", 10, 900)
            flash('Login failed. Check your username and password.', 'danger')

    return render_template('login.html', title='Login', form=form)


# 🔹 TOTP second-step verification
@app.route('/login/totp', methods=['GET', 'POST'])
def login_totp():
    """Second step: verify 6-digit TOTP code after successful password check."""
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        # No pending pre-auth: back to login
        return redirect(url_for('login'))

    user = db.session.get(User, user_id)
    started = session.get('pre_2fa_started', 0)
    if not user or not user.totp_enabled or time.time() - started > 300:
        session.pop('pre_2fa_user_id', None)
        session.pop('pre_2fa_remember', None)
        session.pop('pre_2fa_started', None)
        return redirect(url_for('login'))

    form = TOTPVerifyForm()
    if form.validate_on_submit():
        # 5 tries per 5 min per account: brute-forcing 10^6 codes is impossible
        if hit_rate_limit(f"totp_fail:{user.id}", 5, 300, record=False):
            session.pop('pre_2fa_user_id', None)
            flash('Too many invalid codes. Please log in again later.', 'danger')
            return redirect(url_for('login'))
        if _verify_totp_once(user, form.code.data):
            remember = session.get('pre_2fa_remember', False)
            _start_fresh_session()
            login_user(user, remember=remember)
            flash(f"Welcome {user.username}, you are now logged in!", "success")
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('index'))
        else:
            hit_rate_limit(f"totp_fail:{user.id}", 5, 300)
            flash('Invalid authentication code. Please try again.', 'danger')

    return render_template('login_totp.html', form=form)


# 🔹 Logout a User
@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# 🔹 Admin Dashboard
@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    # Get statistics for dashboard
    total_posts = Post.query.count()
    total_users = User.query.count()
    total_comments = Comment.query.count()
    total_banners = Banner.query.count()
    
    return render_template('admin_dashboard.html', 
                         total_posts=total_posts,
                         total_users=total_users,
                         total_comments=total_comments,
                         total_banners=total_banners)


# 🔹 Donate Page
@app.route('/donate', methods=['GET', 'POST'])
def donate():
    form = EmptyForm()

    if request.method == 'POST':
        # Donations arrive through the external payment widget; recording an
        # amount here is unverified, so only admins may do it (anyone could
        # previously forge the "top donor" shown on every page).
        if not (current_user.is_authenticated and current_user.is_admin) or not form.validate_on_submit():
            abort(403)
        if _action_rate_limited('donate_submit', max_calls=5, window_seconds=3600):
            flash('Too many requests. Please wait.', 'danger')
            return redirect(url_for('donate'))
        try:
            amount = round(float(request.form.get('amount', 0)), 2)
        except (TypeError, ValueError):
            amount = 0
        # reject nan / inf / negative / absurd values
        if not (0 < amount <= 100000):
            flash('Invalid amount.', 'danger')
            return redirect(url_for('donate'))
        if amount > 0:
            new_donor = Donor(name='Anonymous', amount=amount)
            db.session.add(new_donor)
            db.session.commit()
            flash("Thank you for your donation!", "success")
        return redirect(url_for('donate'))

    top_donors = Donor.query.order_by(Donor.amount.desc()).limit(5).all()
    return render_template('donate.html', form=form, top_donors=top_donors)


@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    form = EmptyForm()

    if request.method == 'POST':
        if _action_rate_limited('chat_submit', max_calls=30, window_seconds=300):
            flash('Too many messages. Please wait a bit.', 'danger')
            return redirect(url_for('chat'))
        message_content = request.form.get('message', '').strip()
        file = request.files.get('file')

        # Handle file uploads
        if file and file.filename:
            is_valid, validation_msg = _validate_uploaded_file(
                file,
                allowed_exts=CHAT_ALLOWED_EXTENSIONS,
                max_bytes=MAX_UPLOAD_BYTES
            )
            file_path, file_type = _store_upload(file, 'chat') if is_valid else (None, None)
            if file_path:
                message = Message(
                    sender_id=current_user.id,
                    receiver_id=_get_admin_user_id(),  # actual admin
                    file_path=file_path,
                    file_type=file_type
                )
                message.set_encrypted_content(message_content)
                db.session.add(message)
                db.session.commit()
                publish_mobile_event('new_message', serialize_chat_message(message))
                notify_admin_telegram_new_message(message)
                _notify_admins_new_message(message)
                flash("File sent!", "success")
            else:
                flash(f"File upload failed: {validation_msg or 'invalid file'}", "danger")

        elif message_content:
            if len(message_content) > 5000:
                flash("Message too long (max 5000 characters).", "danger")
                return redirect(url_for('chat'))
            # Save text message (encrypted at rest)
            message = Message(
                sender_id=current_user.id,
                receiver_id=_get_admin_user_id(),  # actual admin
            )
            message.set_encrypted_content(message_content)
            db.session.add(message)
            db.session.commit()
            publish_mobile_event('new_message', serialize_chat_message(message))
            notify_admin_telegram_new_message(message)
            _notify_admins_new_message(message)
            flash("Message sent!", "success")

        return redirect(url_for('chat'))

    # SECURITY: only this user's own conversation with the admins
    # (previously every logged-in user saw ALL private messages).
    messages = _user_conversation_query(current_user.id).order_by(Message.timestamp.asc()).all()

    return render_template('chat.html', form=form, messages=messages)


@socketio.on('connect')
def socket_connect(auth=None):
    # Only authenticated users may open a socket; each joins a private room.
    if not current_user.is_authenticated:
        return False
    join_room(_user_room(current_user.id))


@socketio.on('message')
def handle_message(data):
    if not current_user.is_authenticated:
        disconnect()
        return
    if not isinstance(data, dict):
        return
    msg = str(data.get('msg', '')).strip()
    if not msg or len(msg) > 5000:
        return
    if hit_rate_limit(f"socket_msg:user:{current_user.id}", 30, 300):
        return
    message = Message(sender_id=current_user.id, receiver_id=_get_admin_user_id())
    message.set_encrypted_content(msg)
    db.session.add(message)
    db.session.commit()
    publish_mobile_event('new_message', serialize_chat_message(message))
    notify_admin_telegram_new_message(message)
    _notify_admins_new_message(message)
    # Acknowledge to the sender only (never broadcast private messages).
    emit('message', {'id': message.id, 'msg': msg}, to=_user_room(current_user.id))


@app.route('/admin/chat')
@admin_required
def admin_chat():
    # Get all non-admin users
    users = User.query.filter_by(is_admin=False).order_by(User.username).all()
    
    # Get all messages
    messages = Message.query.order_by(Message.timestamp.asc()).all()
    
    return render_template('admin_chat.html', messages=messages, users=users)


@app.route('/admin/chat/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_chat_user(user_id):
    # Get target user
    target_user = db.get_or_404(User, user_id)

    # Wait-mode endpoint: block shortly and refresh only when new message is available
    wait_mode = request.args.get('wait') == '1'
    last_seen_id = request.args.get('last_seen_id', type=int, default=0)
    if request.method == 'GET' and wait_mode:
        has_new_message = wait_for_conversation_message(current_user.id, user_id, last_seen_id, timeout_seconds=25)
        if has_new_message:
            return redirect(url_for('admin_chat_user', user_id=user_id))
        return redirect(url_for('admin_chat_user', user_id=user_id, wait=1, last_seen_id=last_seen_id))
    
    # Get all non-admin users
    users = User.query.filter_by(is_admin=False).order_by(User.username).all()
    
    # Get messages between admin and this user
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Handle message sending
    if request.method == 'POST':
        if _action_rate_limited('admin_chat_submit', max_calls=60, window_seconds=300):
            flash('Too many messages. Please wait a bit.', 'danger')
            return redirect(url_for('admin_chat_user', user_id=user_id))
        content = request.form.get('content', '').strip()
        file = request.files.get('file')
        
        if content or file:
            message = Message(
                sender_id=current_user.id,
                receiver_id=user_id
            )
            
            # Handle text content
            if content:
                message.set_encrypted_content(content)
            else:
                message.set_encrypted_content("")
            
            # Handle file upload
            if file and file.filename:
                is_valid, validation_msg = _validate_uploaded_file(
                    file,
                    allowed_exts=CHAT_ALLOWED_EXTENSIONS,
                    max_bytes=MAX_UPLOAD_BYTES
                )
                file_path, file_type = _store_upload(file, 'chat') if is_valid else (None, None)
                if file_path:
                    message.file_path = file_path
                    message.file_type = file_type
                else:
                    flash(f'File upload blocked: {validation_msg or "invalid file"}', 'danger')
                    return redirect(url_for('admin_chat_user', user_id=user_id))
            
            db.session.add(message)
            db.session.commit()
            publish_mobile_event('new_message', serialize_chat_message(message))
            
            # Real-time ping to the recipient only (content stays server-side)
            socketio.emit('new_message', {'message_id': message.id}, to=_user_room(user_id))
            
            flash('Message sent!', 'success')
            return redirect(url_for('admin_chat_user', user_id=user_id))

    # Pull Telegram replies (if configured) before rendering chat page
    telegram_fetch_updates(timeout=0)
    # Reload list after potential Telegram sync
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    latest_message_id = messages[-1].id if messages else 0

    return render_template('admin_chat_user.html', 
                         messages=messages, 
                         users=users, 
                         target_user=target_user,
                         latest_message_id=latest_message_id,
                         telegram_bridge_enabled=telegram_is_enabled())


def _can_access_upload(filename):
    """Profile pictures: owner + admins. Chat attachments: sender, receiver
    and admins. Anything else (orphans, unknown, anonymous) is denied."""
    rel = f"uploads/{filename}"
    if not current_user.is_authenticated:
        return False
    owner = User.query.filter(User.profile_picture.in_([rel, os.path.join('uploads', filename)])).first()
    if owner:
        return current_user.is_admin or current_user.id == owner.id
    message = Message.query.filter(Message.file_path.in_([rel, os.path.join('uploads', filename)])).first()
    if not message:
        return False
    return current_user.is_admin or current_user.id in (message.sender_id, message.receiver_id)


def _send_upload(filename):
    if filename != secure_filename(filename) or not _can_access_upload(filename):
        abort(404)
    upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads')
    is_image = _file_ext(filename) in IMAGE_EXTENSIONS
    response = send_from_directory(upload_dir, filename, as_attachment=not is_image)
    # Never let an uploaded file run script in our origin.
    response.headers['Content-Security-Policy'] = "default-src 'none'; img-src 'self'; media-src 'self'; sandbox"
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Route to serve uploaded files (access controlled)."""
    return _send_upload(filename)

@app.route('/static/uploads/<filename>')
def static_uploaded_file(filename):
    """Legacy path, same access control."""
    return _send_upload(filename)


# 🔹 File Upload Route



@app.route('/manage_posts', methods=['GET', 'POST'])
@admin_required
def manage_posts():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        scheduled_date = form.scheduled_date.data
        is_published = bool(form.is_published.data)
        post = Post(
            title=title,
            content=content,
            author_id=current_user.id,
            scheduled_date=scheduled_date,
            is_published=is_published,
            # neither "publish now" nor a date => stays a private draft
            is_draft=not is_published and not scheduled_date
        )
        db.session.add(post)
        db.session.commit()
        
        # Add experience points for creating a post
        current_user.add_experience(10)
        
        # Check and award badges
        check_and_award_badges(current_user)
        
        db.session.commit()
        flash('Post created successfully!', 'success')
        return redirect(url_for('manage_posts'))
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('manage_posts.html', form=form, posts=posts)

@app.route('/manage_users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    users = User.query.all()
    form = EmptyForm()
    return render_template('manage_users.html', users=users, form=form)


@app.route('/manage_comments', methods=['GET', 'POST'])
@admin_required
def manage_comments():
    current_filter = request.args.get('filter', 'all')
    query = Comment.query
    if current_filter == 'recent':
        query = query.filter(Comment.date_posted >= datetime.utcnow() - timedelta(days=7))
    elif current_filter == 'popular':
        query = query.filter(Comment.likes_count >= 5)
    else:
        current_filter = 'all'
    comments = query.order_by(Comment.date_posted.desc()).all()
    form = EmptyForm()
    return render_template('manage_comments.html', comments=comments, form=form, current_filter=current_filter)

@app.route('/site_statistics')
@admin_required
def site_statistics():
    total_users = User.query.count()
    total_admins = User.query.filter_by(is_admin=True).count()
    total_posts = Post.query.count()
    total_comments = Comment.query.count()

    # User with the most posts
    most_active_user = db.session.query(User.username, db.func.count(Post.id).label('post_count'))\
        .join(Post).group_by(User.id).order_by(db.func.count(Post.id).desc()).first()

    return render_template('site_statistics.html',
                           total_users=total_users,
                           total_admins=total_admins,
                           total_posts=total_posts,
                           total_comments=total_comments,
                           most_active_user=most_active_user)

@app.route('/manage_banners', methods=['GET', 'POST'])
@admin_required
def manage_banners():
    form = BannerForm()
    banners = Banner.query.all()
    
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        image_url = form.image_url.data
        link_url = form.link_url.data
        position = form.position.data
        is_active = form.is_active.data
        
        banner = Banner(
            title=title,
            content=content,
            image_url=image_url,
            link_url=link_url,
            position=position,
            is_active=is_active
        )
        
        db.session.add(banner)
        db.session.commit()
        flash('Banner created successfully!', 'success')
        return redirect(url_for('manage_banners'))

    return render_template('manage_banners.html', banners=banners, form=form, delete_form=EmptyForm())

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if _action_rate_limited('upload_file_submit', max_calls=12, window_seconds=300):
        flash('Too many uploads. Please wait a bit.', 'danger')
        return redirect(url_for('chat'))
    if 'file' not in request.files:
        flash('No file selected!', 'danger')
        return redirect(url_for('chat'))

    file = request.files['file']

    if file.filename == '':
        flash('No file uploaded!', 'danger')
        return redirect(url_for('chat'))

    is_valid, validation_msg = _validate_uploaded_file(
        file,
        allowed_exts=UPLOAD_FILE_ALLOWED_EXTENSIONS,
        max_bytes=MAX_UPLOAD_BYTES,
        image_only=True
    )
    if not is_valid:
        flash(f'Invalid file type! {validation_msg}', 'danger')
        return redirect(url_for('chat'))

    # Random name + full metadata strip, then attach it to the user's chat
    # (the old code kept the user's filename: files could overwrite each other).
    file_path, file_type = _store_upload(file, 'chat')
    if not file_path:
        flash('Invalid image file!', 'danger')
        return redirect(url_for('chat'))
    message = Message(sender_id=current_user.id, receiver_id=_get_admin_user_id(),
                      file_path=file_path, file_type=file_type)
    message.set_encrypted_content('')
    db.session.add(message)
    db.session.commit()
    publish_mobile_event('new_message', serialize_chat_message(message))
    notify_admin_telegram_new_message(message)
    _notify_admins_new_message(message)

    flash('Image uploaded (metadata removed).', 'success')
    return redirect(url_for('chat'))

@app.route('/manage_pages', methods=['GET', 'POST'])
@admin_required
def manage_pages():
    pages = StaticPage.query.all()
    form = StaticPageForm()

    if form.validate_on_submit():
        slug = _unique_page_slug(form.slug.data or form.title.data)
        page = StaticPage(title=form.title.data, slug=slug, content=form.content.data)
        db.session.add(page)
        db.session.commit()
        flash("Page created successfully!", "success")
        return redirect(url_for('manage_pages'))

    return render_template('manage_pages.html', pages=pages, form=form)




@app.route('/demote_user/<int:user_id>', methods=['POST'])
@admin_required
def demote_user(user_id):
    user = db.get_or_404(User, user_id)

    if user.is_admin:
        if User.query.filter_by(is_admin=True).count() <= 1:
            flash('Cannot demote the last admin.', 'danger')
            return redirect(url_for('manage_users'))
        user.is_admin = False
        db.session.commit()
        app.logger.warning("SECURITY admin %s demoted user %s", current_user.id, user.id)
        flash(f'User {user.username} has been demoted.', 'success')

    return redirect(url_for('manage_users'))


@app.route('/create_page', methods=['GET', 'POST'])
@admin_required
def create_page():
    form = StaticPageForm()

    if form.validate_on_submit():
        # slug is NOT NULL + unique: the old code crashed here (500)
        slug = _unique_page_slug(form.slug.data or form.title.data)
        page = StaticPage(title=form.title.data, slug=slug, content=form.content.data)
        db.session.add(page)
        db.session.commit()
        flash('New page created!', 'success')
        return redirect(url_for('manage_pages'))

    return render_template('create_page.html', form=form)


def _unique_page_slug(text, exclude_id=None):
    base = re.sub(r'[^a-z0-9]+', '-', (text or '').lower()).strip('-')[:90] or 'page'
    slug, n = base, 2
    while True:
        existing = StaticPage.query.filter_by(slug=slug).first()
        if not existing or existing.id == exclude_id:
            return slug
        slug = f"{base}-{n}"
        n += 1


@app.route('/page/<slug>')
def view_page(slug):
    page = StaticPage.query.filter_by(slug=slug).first_or_404()
    return render_template('view_page.html', page=page)


@app.route('/edit_page/<page_name>', methods=['GET', 'POST'])
@admin_required
def edit_page(page_name):
    page = StaticPage.query.filter_by(slug=page_name).first_or_404()
    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()[:100]
        content = request.form.get('content') or ''
        if not title or not content.strip():
            flash('Title and content are required.', 'danger')
            return redirect(url_for('edit_page', page_name=page.slug))
        page.title = title
        page.content = content
        page.date_modified = datetime.utcnow()
        db.session.commit()
        flash('Page updated!', 'success')
        return redirect(url_for('manage_pages'))
    return render_template('edit_page.html', page=page)


@app.route('/delete_page/<int:page_id>', methods=['POST'])
@admin_required
def delete_page(page_id):
    page = db.get_or_404(StaticPage, page_id)
    db.session.delete(page)
    db.session.commit()
    flash('Page deleted.', 'success')
    return redirect(url_for('manage_pages'))


@app.route('/edit_banner/<int:banner_id>', methods=['GET', 'POST'])
@admin_required
def edit_banner(banner_id):
    banner = db.get_or_404(Banner, banner_id)
    form = BannerForm(obj=banner)
    if form.validate_on_submit():
        form.populate_obj(banner)
        db.session.commit()
        flash('Banner updated!', 'success')
        return redirect(url_for('manage_banners'))
    return render_template('manage_banners.html', banners=Banner.query.all(), form=form,
                           delete_form=EmptyForm(),
                           form_action=url_for('edit_banner', banner_id=banner.id))


@app.route('/delete_banner/<int:banner_id>', methods=['POST'])
@admin_required
def delete_banner(banner_id):
    banner = db.get_or_404(Banner, banner_id)
    db.session.delete(banner)
    db.session.commit()
    flash('Banner deleted.', 'success')
    return redirect(url_for('manage_banners'))

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@admin_required
def delete_post(post_id):
    post = db.get_or_404(Post, post_id)
    _delete_post_and_children(post)
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('manage_posts'))

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@admin_required
def edit_post(post_id):
    post = db.get_or_404(Post, post_id)
    form = PostForm(obj=post)

    if form.validate_on_submit():
        last_version = db.session.query(db.func.max(Revision.version)).filter_by(post_id=post.id).scalar() or 0
        db.session.add(Revision(post_id=post.id, content=post.content, version=last_version + 1))
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Post updated successfully!', 'success')
        return redirect(url_for('manage_posts'))

    return render_template('edit_post.html', form=form, post=post)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = db.get_or_404(User, user_id)

    if user.id == current_user.id:
        flash('You cannot delete your own account from here.', 'danger')
        return redirect(url_for('manage_users'))
    if user.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
        flash('Cannot delete the last admin.', 'danger')
        return redirect(url_for('manage_users'))

    username = user.username
    _delete_user_and_data(user, new_post_owner_id=current_user.id)
    app.logger.warning("SECURITY admin %s deleted user %s", current_user.id, user_id)
    flash(f'User {username} deleted.', 'success')

    return redirect(url_for('manage_users'))


@app.route('/promote_user/<int:user_id>', methods=['POST'])
@admin_required
def promote_user(user_id):
    user = db.get_or_404(User, user_id)
    user.is_admin = True
    db.session.commit()
    app.logger.warning("SECURITY admin %s promoted user %s to admin", current_user.id, user.id)
    flash(f"{user.username} has been promoted to admin.", "success")
    return redirect(url_for('manage_users'))






@app.route("/delete_comment/<int:comment_id>/<int:post_id>", methods=["POST"]) 
@rate_limit('delete_comment', max_calls=15, window_seconds=300)
@login_required
def delete_comment(comment_id, post_id):
    comment = db.get_or_404(Comment, comment_id)

    # Admin can delete everything, otherwise user can only delete their own comments
    if not current_user.is_admin and comment.author_id != current_user.id:
        abort(403)  # Forbidden access

    Like.query.filter_by(comment_id=comment.id).delete(synchronize_session=False)
    if comment.replies:
        # keep the thread structure, erase the content
        comment.deleted = True
        comment.content = '[deleted]'
    else:
        Notification.query.filter_by(related_comment_id=comment.id).delete(synchronize_session=False)
        db.session.delete(comment)
    db.session.commit()
    flash("Comment deleted successfully!", "success")
    return redirect(url_for("post_detail", post_id=post_id))



@app.route("/posts")
def post_list():
    posts = _visible_posts_query().order_by(Post.date_posted.desc()).all()
    return render_template("post_list.html", posts=posts)

@app.route("/reply_to_comment/<int:post_id>/<int:comment_id>", methods=["POST"])
@rate_limit('reply_to_comment', max_calls=10, window_seconds=300)
@login_required
def reply_to_comment(post_id, comment_id):
    post = _visible_posts_query().filter(Post.id == post_id).first_or_404()
    parent_comment = db.get_or_404(Comment, comment_id)
    if parent_comment.post_id != post.id or parent_comment.deleted:
        abort(404)

    form = CommentForm()

    if form.validate_on_submit():
        reply = Comment(
            content=form.content.data.strip(),  # raw BBCode, sanitized at render
            author=current_user,
            post_id=post.id,
            parent_id=parent_comment.id
        )
        db.session.add(reply)
        db.session.commit()
        
        # Add experience points for reply
        current_user.add_experience(2)
        
        # Create notification for parent comment author
        if parent_comment.author_id and parent_comment.author_id != current_user.id:
            notification = Notification(
                user_id=parent_comment.author_id,
                type='reply',
                title='New reply!',
                message='Someone replied to your comment',
                related_post_id=post.id,
                related_comment_id=reply.id
            )
            db.session.add(notification)
            
            _notify_user(parent_comment.author_id, {
                'type': 'reply',
                'title': 'New reply!',
                'message': 'Someone replied to your comment',
            })
        
        # Check and award badges
        check_and_award_badges(current_user)
        
        db.session.commit()
        flash("Your reply has been added!", "success")
        return redirect(url_for("post_detail", post_id=post.id))

    flash("Error submitting your reply. Please make sure your reply is not empty.", "danger")
    return redirect(url_for("post_detail", post_id=post.id))


@app.route("/edit_comment/<int:comment_id>/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_comment(comment_id, post_id):
    comment = db.get_or_404(Comment, comment_id)
    post = db.get_or_404(Post, comment.post_id)

    # Admins can edit every comment, users only their own
    if not current_user.is_admin and comment.author_id != current_user.id:
        abort(403)  # Forbidden access
    if comment.deleted:
        abort(404)

    form = CommentForm()
    if form.validate_on_submit():
        if _action_rate_limited('edit_comment_submit', max_calls=20, window_seconds=300):
            flash('Too many edits. Please wait.', 'danger')
            return redirect(url_for('post_detail', post_id=post.id))
        comment.content = form.content.data.strip()
        db.session.commit()
        flash("Comment updated!", "success")
        return redirect(url_for("post_detail", post_id=post.id))

    form.content.data = comment.content
    return render_template("edit_comment.html", title="Edit Comment", form=form, post=post, comment=comment)  # 🔥 Passe `post`


# 🔹 Likes
@app.route('/like_post/<int:post_id>', methods=['POST'])
@rate_limit('like_post', max_calls=20, window_seconds=300)
@login_required
def like_post(post_id):
    post = _visible_posts_query().filter(Post.id == post_id).first_or_404()
    
    # Check if user already liked this post
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    
    if existing_like:
        # Remove like
        db.session.delete(existing_like)
        post.likes_count = max(0, post.likes_count - 1)
        flash('Like removed!', 'info')
    else:
        # Add like
        like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        post.likes_count += 1
        
        # Add experience points to post author
        if post.author_id != current_user.id:
            post.author.add_experience(5)
            
            # Create notification for author
            notification = Notification(
                user_id=post.author_id,
                type='like',
                title='New like!',
                message=f'Someone liked your article "{post.title}"',
                related_post_id=post_id
            )
            db.session.add(notification)
            
            _notify_user(post.author_id, {
                'type': 'like',
                'title': 'New like!',
                'message': f'Someone liked your article "{post.title}"',
            })
        
        flash('Article liked!', 'success')
    
    db.session.commit()
    return redirect(url_for('post_detail', post_id=post_id))


@app.route('/like_comment/<int:comment_id>', methods=['POST'])
@rate_limit('like_comment', max_calls=30, window_seconds=300)
@login_required
def like_comment(comment_id):
    comment = db.get_or_404(Comment, comment_id)
    
    # Check if user already liked this comment
    existing_like = Like.query.filter_by(user_id=current_user.id, comment_id=comment_id).first()
    
    if existing_like:
        # Remove like
        db.session.delete(existing_like)
        comment.likes_count = max(0, comment.likes_count - 1)
        flash('Like removed!', 'info')
    else:
        # Add like
        like = Like(user_id=current_user.id, comment_id=comment_id)
        db.session.add(like)
        comment.likes_count += 1
        
        # Add experience points to comment author
        if comment.author_id and comment.author_id != current_user.id:
            comment.author.add_experience(2)
            
            # Notify the author
            notification = Notification(
                user_id=comment.author_id,
                type='like',
                title='Comment liked!',
                message='Someone liked your comment',
                related_comment_id=comment_id,
                related_post_id=comment.post_id
            )
            db.session.add(notification)
            
            _notify_user(comment.author_id, {
                'type': 'like',
                'title': 'Comment liked!',
                'message': 'Someone liked your comment',
            })
        
        flash('Comment liked!', 'success')
    
    db.session.commit()
    return redirect(url_for('post_detail', post_id=comment.post_id))


# 🔹 Notifications
@app.route('/notifications')
@login_required
def notifications():
    user_notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc()).all()
    form = EmptyForm()
    return render_template('notifications.html', notifications=user_notifications, form=form)


@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = db.get_or_404(Notification, notification_id)
    if notification.user_id == current_user.id:
        notification.is_read = True
        db.session.commit()
    return redirect(url_for('notifications'))


@app.route('/mark_all_notifications_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False)\
        .update({'is_read': True})
    db.session.commit()
    flash('All notifications were marked as read!', 'success')
    return redirect(url_for('notifications'))


# 🔹 Badges and levels
@app.route('/profile/<int:user_id>')
def user_profile(user_id):
    user = db.get_or_404(User, user_id)
    user_posts = Post.query.filter_by(author_id=user_id, is_published=True).order_by(Post.date_posted.desc()).limit(5).all()
    user_comments = Comment.query.filter_by(author_id=user_id).order_by(Comment.date_posted.desc()).limit(5).all()
    
    # Statistics
    total_posts = Post.query.filter_by(author_id=user_id, is_published=True).count()
    total_comments = Comment.query.filter_by(author_id=user_id).count()
    total_likes_received = db.session.query(db.func.sum(Post.likes_count))\
        .filter(Post.author_id == user_id).scalar() or 0
    
    return render_template('user_profile.html', 
                         user=user, 
                         user_posts=user_posts,
                         user_comments=user_comments,
                         total_posts=total_posts,
                         total_comments=total_comments,
                         total_likes_received=total_likes_received)


# 🔹 Create the default badges (run once)
@app.route('/init_badges')
@admin_required
def init_badges():
    create_default_badges()
    flash('Default badges created successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


# 🔹 Edit profile
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = ProfileEditForm(original_username=current_user.username)
    
    if form.validate_on_submit():
        if _action_rate_limited('edit_profile_submit', max_calls=10, window_seconds=300):
            flash('Too many updates. Please wait.', 'danger')
            return redirect(url_for('edit_profile'))
        # Update the username
        current_user.username = form.username.data
        
        # Handle profile picture upload
        if form.profile_picture.data:
            file = form.profile_picture.data
            is_valid, validation_msg = _validate_uploaded_file(
                file,
                allowed_exts=PROFILE_ALLOWED_EXTENSIONS,
                max_bytes=min(MAX_UPLOAD_BYTES, 3 * 1024 * 1024),
                image_only=True
            )
            file_path = None
            if is_valid:
                file_path, _ = _store_upload(file, 'profile')
            if file_path:
                # Remove old photo if it exists (only inside the uploads folder)
                _remove_upload_file(current_user.profile_picture)
                current_user.profile_picture = file_path
            else:
                validation_msg = validation_msg or 'invalid image'
                flash(f'Profile picture rejected: {validation_msg}', 'danger')
                return redirect(url_for('edit_profile'))
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_profile', user_id=current_user.id))
    
    # Pre-fill form with current data
    form.username.data = current_user.username
    
    return render_template('edit_profile.html', form=form)


# ─────────────────────────────────────────────────────────────────
#  TOTP / 2FA routes
# ─────────────────────────────────────────────────────────────────

def _totp_qr_data_uri(secret: str, username: str) -> str:
    """Return a data: URI PNG of the provisioning QR code (no file on disk)."""
    import qrcode
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name='MyBlog'
    )
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode('ascii')
    return f'data:image/png;base64,{b64}'


@app.route('/totp/setup', methods=['GET', 'POST'])
@login_required
def totp_setup():
    """Generate a new TOTP secret and show the QR code.
    On POST with a valid 6-digit code, activate 2FA for the user.
    """
    if current_user.totp_enabled:
        flash('Two-factor authentication is already active.', 'info')
        return redirect(url_for('edit_profile'))

    form = TOTPSetupForm()

    # Generate (or reuse pending) secret stored in session
    if 'totp_pending_secret' not in session:
        session['totp_pending_secret'] = pyotp.random_base32()

    pending_secret = session['totp_pending_secret']

    if form.validate_on_submit():
        if hit_rate_limit(f"totp_setup_fail:{current_user.id}", 10, 300, record=False):
            flash('Too many attempts. Please wait a few minutes.', 'danger')
            return redirect(url_for('totp_setup'))
        totp = pyotp.TOTP(pending_secret)
        if totp.verify(form.code.data.strip(), valid_window=1):
            current_user.totp_secret = pending_secret
            current_user.totp_enabled = True
            db.session.commit()
            session.pop('totp_pending_secret', None)
            flash('Two-factor authentication has been enabled!', 'success')
            return redirect(url_for('user_profile', user_id=current_user.id))
        else:
            hit_rate_limit(f"totp_setup_fail:{current_user.id}", 10, 300)
            flash('Invalid code. Please try again.', 'danger')

    qr_uri = _totp_qr_data_uri(pending_secret, current_user.username)
    return render_template(
        'totp_setup.html',
        form=form,
        qr_uri=qr_uri,
        totp_secret=pending_secret
    )


@app.route('/totp/disable', methods=['GET', 'POST'])
@login_required
def totp_disable():
    """Disable 2FA after confirming current password + a valid TOTP code."""
    if not current_user.totp_enabled:
        flash('Two-factor authentication is not currently active.', 'info')
        return redirect(url_for('edit_profile'))

    form = TOTPDisableForm()

    if form.validate_on_submit():
        fail_key = f"totp_disable_fail:{current_user.id}"
        if hit_rate_limit(fail_key, 5, 900, record=False):
            flash('Too many failed attempts. Please wait 15 minutes.', 'danger')
            return render_template('totp_disable.html', form=form)
        if not _check_user_password(current_user, form.password.data):
            hit_rate_limit(fail_key, 5, 900)
            flash('Incorrect password.', 'danger')
            return render_template('totp_disable.html', form=form)

        if not _verify_totp_once(current_user, form.code.data):
            hit_rate_limit(fail_key, 5, 900)
            flash('Invalid authentication code.', 'danger')
            return render_template('totp_disable.html', form=form)

        current_user.totp_enabled = False
        current_user.totp_secret = None
        db.session.commit()
        flash('Two-factor authentication has been disabled.', 'success')
        return redirect(url_for('user_profile', user_id=current_user.id))

    return render_template('totp_disable.html', form=form)
