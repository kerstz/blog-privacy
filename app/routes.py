from flask import render_template, url_for, flash, redirect, request, abort, send_from_directory, session
from flask_login import login_user, current_user, logout_user, login_required
from app import app, db, bcrypt, socketio
from app.utils import parse_bbcode
from app.forms import LoginForm, RegistrationForm, PostForm, CommentForm, EmptyForm, BannerForm, StaticPageForm, ContactForm, ProfileEditForm
from app.models import User, Post, Comment, Revision, Banner, StaticPage, Message, Donor, Like, Notification, Badge
from app.utils import rate_limit, role_required, process_image_file
from functools import wraps
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from flask_socketio import emit
from werkzeug.utils import secure_filename
import re
import os
from PIL import Image
import piexif


# 🔹 Helper: Parse BBCode Image Tags
def parse_img_tags(content):
    img_tag_pattern = re.compile(r'\[img\](.*?)\[/img\]', re.IGNORECASE)
    return img_tag_pattern.sub(r'<img src="\1" alt="Image" style="max-width:100%; height:auto;">', content)


# 🔹 Admin-only Route Decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Access denied. Only admins can view this page.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


# 🔹 Home Page
@app.route('/')
def index():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
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
        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html', form=form)


# 🔹 View a Blog Post
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    form = CommentForm()
    # Increment view counter once per session
    if request.method == 'GET':
        viewed_posts = session.get('viewed_posts', [])
        if post_id not in viewed_posts:
            post.views_count = (post.views_count or 0) + 1
            db.session.commit()
            viewed_posts.append(post_id)
            session['viewed_posts'] = viewed_posts

    if form.validate_on_submit():
        if current_user.is_authenticated:
            content = form.content.data.strip()
            if content:
                comment = Comment(content=parse_bbcode(content), post_id=post.id, author_id=current_user.id)
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
                    
                    # Émettre une notification temps réel
                    socketio.emit('notification', {
                        'type': 'comment',
                        'title': 'Nouveau commentaire !',
                        'message': f'{current_user.username} a commenté votre article "{post.title}"',
                        'user_id': post.author_id
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

    # BBCode render (server-side)
    post.content = parse_bbcode(post.content)

    return render_template('post_detail.html', post=post, form=form)


# 🔹 Register a User
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register', form=form)


# 🔹 Login a User
@app.route('/login', methods=['GET', 'POST'])
@rate_limit('login', max_calls=5, window_seconds=300)
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard') if current_user.is_admin else url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember_me.data)
            flash(f"Welcome {user.username}, you are now logged in!", "success")
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'danger')

    return render_template('login.html', title='Login', form=form)


# 🔹 Logout a User
@app.route('/logout')
def logout():
    logout_user()
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
        amount = float(request.form.get('amount', 0))
        if amount > 0:
            new_donor = Donor(name='Anonymous', amount=amount)
            db.session.add(new_donor)
            db.session.commit()
            flash("Thank you for your donation!", "success")
        return redirect(url_for('donate'))

    top_donors = Donor.query.order_by(Donor.amount.desc()).limit(5).all()
    return render_template('donate.html', form=form, top_donors=top_donors)


# File Upload Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf', 'doc', 'docx', 'txt', 
                      'zip', 'rar', '7z', 'mp3', 'mp4', 'avi', 'mov', 'mkv', 'csv', 
                      'xls', 'xlsx', 'ppt', 'pptx', 'json', 'xml', 'svg', 'webm', 'ogg'}

# Function to check if file extension is allowed
def allowed_file(filename):
    # Allow any file extension for maximum flexibility
    return '.' in filename

# Function to modify image metadata
def modify_exif_data(file_path):
    try:
        image = Image.open(file_path)
        exif_dict = piexif.load(image.info.get('exif', b''))

        # Remove GPS information
        if 'GPS' in exif_dict:
            exif_dict['GPS'] = {}

        # Add custom tag
        exif_dict['0th'][piexif.ImageIFD.Make] = "Modified"
        exif_dict['0th'][piexif.ImageIFD.Model] = "Edited"
        exif_dict['0th'][piexif.ImageIFD.Software] = "ChatUploader"

        exif_bytes = piexif.dump(exif_dict)
        image.save(file_path, "jpeg", exif=exif_bytes)
    except Exception as e:
        print(f"EXIF modification error: {e}")

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    form = EmptyForm()

    if request.method == 'POST':
        message_content = request.form.get('message', '').strip()
        file = request.files.get('file')

        # Handle file uploads
        if file and file.filename:
            if allowed_file(file.filename):  # Check if file is allowed
                filename = secure_filename(file.filename)
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)

                # Modify image metadata if it's an image
                if file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp')):
                    modify_exif_data(file_path)

                # Save message with file
                message = Message(
                    sender_id=current_user.id,
                    receiver_id=1,  # Admin ID = 1
                    content=f"📁 Sent a file: <a href='/uploads/{filename}' target='_blank'>{filename}</a>"
                )
                db.session.add(message)
                db.session.commit()
                flash("Image sent!", "success")
            else:
                flash("File upload failed!", "danger")

        elif message_content:
            # Save text message
            message = Message(
                sender_id=current_user.id,
                receiver_id=1,  # Admin ID = 1
                content=message_content
            )
            db.session.add(message)
            db.session.commit()
            flash("Message sent!", "success")

        return redirect(url_for('chat'))

    # Get messages from most recent to oldest
    messages = Message.query.order_by(Message.timestamp.desc()).all()

    return render_template('chat.html', form=form, messages=messages)

@socketio.on('message')
def handle_message(data):
    msg = data.get('msg', '').strip()
    sender_id = current_user.id if current_user.is_authenticated else None
    receiver_id = 1  # L'admin reçoit les messages

    if msg and sender_id:
        message = Message(sender_id=sender_id, receiver_id=receiver_id, content=msg)
        db.session.add(message)
        db.session.commit()

        # Émet le message à tous les clients connectés
        emit('message', {"username": current_user.username, "msg": msg}, broadcast=True)


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
    target_user = User.query.get_or_404(user_id)
    
    # Get all non-admin users
    users = User.query.filter_by(is_admin=False).order_by(User.username).all()
    
    # Get messages between admin and this user
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Gérer l'envoi de message
    if request.method == 'POST':
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
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"chat_{current_user.id}_{user_id}_{timestamp}_{filename}"
                    file_path = os.path.join('uploads', filename)
                    file.save(file_path)
                    # Media pipeline
                    processed = process_image_file(file_path)
                    if processed != file_path:
                        try:
                            os.remove(file_path)
                        except Exception:
                            pass
                        file_path = processed
                    message.file_path = file_path
                    message.file_type = get_file_type(file.filename)
                else:
                    flash('File format not supported.', 'danger')
                    return redirect(url_for('admin_chat_user', user_id=user_id))
            
            db.session.add(message)
            db.session.commit()
            
            # Emit message via SocketIO
            socketio.emit('message', {
                'username': current_user.username,
                'msg': content if content else f"File sent: {file.filename}",
                'receiver_id': user_id,
                'file_path': message.file_path,
                'file_type': message.file_type
            })
            
            flash('Message sent!', 'success')
            return redirect(url_for('admin_chat_user', user_id=user_id))
    
    return render_template('admin_chat_user.html', 
                         messages=messages, 
                         users=users, 
                         target_user=target_user)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Route to serve uploaded files"""
    upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads')
    return send_from_directory(upload_dir, filename)

@app.route('/static/uploads/<filename>')
def static_uploaded_file(filename):
    """Route to serve uploaded files from static/uploads"""
    upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads')
    return send_from_directory(upload_dir, filename)


# 🔹 File Upload Route



@app.route('/manage_posts', methods=['GET', 'POST'])
@admin_required
def manage_posts():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        scheduled_date = form.scheduled_date.data or datetime.utcnow()
        is_published = form.is_published.data
        post = Post(
            title=title,
            content=content,
            author_id=current_user.id,
            scheduled_date=scheduled_date,
            is_published=is_published
        )
        db.session.add(post)
        db.session.commit()
        
        # Add experience points for creating a post
        current_user.add_experience(10)
        
        # Vérifier et attribuer les badges
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
    comments = Comment.query.order_by(Comment.date_posted.desc()).all()
    form = EmptyForm()
    return render_template('manage_comments.html', comments=comments, form=form)

@app.route('/site_statistics')
@admin_required
def site_statistics():
    total_users = User.query.count()
    total_admins = User.query.filter_by(is_admin=True).count()
    total_posts = Post.query.count()
    total_comments = Comment.query.count()

    # Trouver l'utilisateur avec le plus de posts
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
        is_active = form.is_active.data
        
        banner = Banner(
            title=title,
            content=content,
            image_url=image_url,
            link_url=link_url,
            is_active=is_active
        )
        
        db.session.add(banner)
        db.session.commit()
        flash('Banner created successfully!', 'success')
        return redirect(url_for('manage_banners'))

    return render_template('manage_banners.html', banners=banners, form=form)



ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_type(filename):
    """Détermine le type de fichier basé sur l'extension"""
    if not filename:
        return 'unknown'
    
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext in ['png', 'jpg', 'jpeg', 'gif']:
        return 'image'
    elif ext in ['mp4', 'avi', 'mov', 'wmv']:
        return 'video'
    else:
        return 'file'

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file selected!', 'danger')
        return redirect(url_for('chat'))

    file = request.files['file']

    if file.filename == '':
        flash('No file uploaded!', 'danger')
        return redirect(url_for('chat'))

    if not allowed_file(file.filename):
        flash('Invalid file type! Only PNG, JPG, JPEG, and GIF are allowed.', 'danger')
        return redirect(url_for('chat'))

    # Secure filename
    filename = secure_filename(file.filename)
    file_path = os.path.join('uploads', filename)

    # Save file
    file.save(file_path)

    # Verify if it's a valid image by trying to open it with PIL
    try:
        with Image.open(file_path) as img:
            img.verify()  # Quick integrity check
    except Exception:
        os.remove(file_path)  # Remove file if it's not a valid image
        flash('Invalid image file!', 'danger')
        return redirect(url_for('chat'))

    # Modify image metadata
    modify_exif_data(file_path)

    flash('Image uploaded and metadata modified successfully!', 'success')
    return redirect(url_for('chat'))

@app.route('/manage_pages', methods=['GET', 'POST'])
@admin_required
def manage_pages():
    pages = StaticPage.query.all()
    form = StaticPageForm()

    if form.validate_on_submit():
        page = StaticPage(title=form.title.data, content=form.content.data)
        db.session.add(page)
        db.session.commit()
        flash("Page created successfully!", "success")
        return redirect(url_for('manage_pages'))

    return render_template('manage_pages.html', pages=pages, form=form)




@app.route('/demote_user/<int:user_id>', methods=['POST'])
@admin_required
def demote_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.is_admin:
        user.is_admin = False
        db.session.commit()
        flash(f'User {user.username} has been demoted.', 'success')

    return redirect(url_for('manage_users'))


@app.route('/create_page', methods=['GET', 'POST'])
@admin_required
def create_page():
    form = StaticPageForm()

    if form.validate_on_submit():
        page = StaticPage(title=form.title.data, content=form.content.data)
        db.session.add(page)
        db.session.commit()
        flash('New page created!', 'success')
        return redirect(url_for('manage_pages'))

    return render_template('create_page.html', form=form)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@admin_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('manage_posts'))

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@admin_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    form = PostForm(obj=post)

    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Post updated successfully!', 'success')
        return redirect(url_for('manage_posts'))

    return render_template('edit_post.html', form=form, post=post)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} deleted.', 'success')

    return redirect(url_for('manage_users'))


@app.route('/promote_user/<int:user_id>', methods=['POST'])
@admin_required
def promote_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    flash(f"{user.username} has been promoted to admin.", "success")
    return redirect(url_for('manage_users'))






@app.route("/delete_comment/<int:comment_id>/<int:post_id>", methods=["POST"]) 
@rate_limit('delete_comment', max_calls=15, window_seconds=300)
@login_required
def delete_comment(comment_id, post_id):
    comment = Comment.query.get_or_404(comment_id)

    # Admin can delete everything, otherwise user can only delete their own comments
    if not current_user.is_admin and comment.author_id != current_user.id:
        abort(403)  # Forbidden access

    db.session.delete(comment)
    db.session.commit()
    flash("Comment deleted successfully!", "success")
    return redirect(url_for("post_detail", post_id=post_id))



@app.route("/posts")
def post_list():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template("post_list.html", posts=posts)

@app.route("/reply_to_comment/<int:post_id>/<int:comment_id>", methods=["POST"])
@rate_limit('reply_to_comment', max_calls=10, window_seconds=300)
@login_required
def reply_to_comment(post_id, comment_id):
    post = Post.query.get_or_404(post_id)
    parent_comment = Comment.query.get_or_404(comment_id)

    form = CommentForm()

    print("Received form data:", request.form)  # Débugger ce qui est envoyé par le formulaire

    if form.validate_on_submit():
        reply = Comment(
            content=form.content.data,
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
                title='Nouvelle réponse !',
                message=f'{current_user.username} a répondu à votre commentaire',
                related_post_id=post.id,
                related_comment_id=reply.id
            )
            db.session.add(notification)
            
            # Émettre une notification temps réel
            socketio.emit('notification', {
                'type': 'reply',
                'title': 'Nouvelle réponse !',
                'message': f'{current_user.username} a répondu à votre commentaire',
                'user_id': parent_comment.author_id
            })
        
        # Vérifier et attribuer les badges
        check_and_award_badges(current_user)
        
        db.session.commit()
        flash("Your reply has been added!", "success")
        return redirect(url_for("post_detail", post_id=post.id))

    print("Form validation errors:", form.errors)  # Afficher les erreurs du formulaire
    flash("Error submitting your reply. Please make sure your reply is not empty.", "danger")
    return redirect(url_for("post_detail", post_id=post.id))


@app.route("/edit_comment/<int:comment_id>/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_comment(comment_id, post_id):
    comment = Comment.query.get_or_404(comment_id)
    post = Post.query.get_or_404(post_id)

    # L'admin peut modifier tous les commentaires, sinon l'utilisateur ne peut modifier que les siens
    if not current_user.is_admin and comment.author_id != current_user.id:
        abort(403)  # Forbidden access

    form = CommentForm()
    if form.validate_on_submit():
        comment.content = form.content.data
        db.session.commit()
        flash("Comment updated!", "success")
        return redirect(url_for("post_detail", post_id=post_id))

    form.content.data = comment.content
    return render_template("edit_comment.html", title="Edit Comment", form=form, post=post, comment=comment)  # 🔥 Passe `post`


# 🔹 Système de Likes/Upvotes
@app.route('/like_post/<int:post_id>', methods=['POST'])
@rate_limit('like_post', max_calls=20, window_seconds=300)
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    
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
            
            # Émettre une notification temps réel
            socketio.emit('notification', {
                'type': 'like',
                'title': 'Nouveau like !',
                'message': f'{current_user.username} a aimé votre article "{post.title}"',
                'user_id': post.author_id
            })
        
        flash('Article aimé !', 'success')
    
    db.session.commit()
    return redirect(url_for('post_detail', post_id=post_id))


@app.route('/like_comment/<int:comment_id>', methods=['POST'])
@login_required
def like_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
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
            
            # Créer une notification pour l'auteur
            notification = Notification(
                user_id=comment.author_id,
                type='like',
                title='Commentaire aimé !',
                message=f'{current_user.username} a aimé votre commentaire',
                related_comment_id=comment_id,
                related_post_id=comment.post_id
            )
            db.session.add(notification)
            
            # Émettre une notification temps réel
            socketio.emit('notification', {
                'type': 'like',
                'title': 'Commentaire aimé !',
                'message': f'{current_user.username} a aimé votre commentaire',
                'user_id': comment.author_id
            })
        
        flash('Commentaire aimé !', 'success')
    
    db.session.commit()
    return redirect(url_for('post_detail', post_id=comment.post_id))


# 🔹 Système de Notifications
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
    notification = Notification.query.get_or_404(notification_id)
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
    flash('Toutes les notifications ont été marquées comme lues !', 'success')
    return redirect(url_for('notifications'))


# 🔹 Système de Badges et Niveaux
@app.route('/profile/<int:user_id>')
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    user_posts = Post.query.filter_by(author_id=user_id, is_published=True).order_by(Post.date_posted.desc()).limit(5).all()
    user_comments = Comment.query.filter_by(author_id=user_id).order_by(Comment.date_posted.desc()).limit(5).all()
    
    # Calculer les statistiques
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


# Function to create default badges
def create_default_badges():
    """Crée les badges par défaut du système"""
    default_badges = [
        {
            'name': 'Premier Post',
            'description': 'A publié son premier article',
            'icon': 'fas fa-feather-alt',
            'color': '#8b93ff',
            'condition': 'first_post',
            'points_reward': 50
        },
        {
            'name': 'Commentateur Actif',
            'description': 'A publié 10 commentaires',
            'icon': 'fas fa-comments',
            'color': '#51cf66',
            'condition': '10_comments',
            'points_reward': 30
        },
        {
            'name': 'Auteur Prolifique',
            'description': 'A publié 5 articles',
            'icon': 'fas fa-pen-fancy',
            'color': '#ffd43b',
            'condition': '5_posts',
            'points_reward': 100
        },
        {
            'name': 'Populaire',
            'description': 'Un de ses articles a reçu 10 likes',
            'icon': 'fas fa-fire',
            'color': '#ff6b6b',
            'condition': '10_likes_post',
            'points_reward': 75
        },
        {
            'name': 'Niveau 5',
            'description': 'A atteint le niveau 5',
            'icon': 'fas fa-star',
            'color': '#9c88ff',
            'condition': 'level_5',
            'points_reward': 0
        }
    ]
    
    for badge_data in default_badges:
        existing_badge = Badge.query.filter_by(name=badge_data['name']).first()
        if not existing_badge:
            badge = Badge(**badge_data)
            db.session.add(badge)
    
    db.session.commit()


# Function to check and award badges
def check_and_award_badges(user):
    """Vérifie et attribue les badges à un utilisateur"""
    badges = Badge.query.all()
    
    for badge in badges:
        if badge.name not in user.get_badges():
            should_award = False
            
            if badge.condition == 'first_post':
                should_award = Post.query.filter_by(author_id=user.id, is_published=True).count() >= 1
            elif badge.condition == '10_comments':
                should_award = Comment.query.filter_by(author_id=user.id).count() >= 10
            elif badge.condition == '5_posts':
                should_award = Post.query.filter_by(author_id=user.id, is_published=True).count() >= 5
            elif badge.condition == '10_likes_post':
                should_award = db.session.query(Post).filter_by(author_id=user.id)\
                    .filter(Post.likes_count >= 10).first() is not None
            elif badge.condition == 'level_5':
                should_award = user.level >= 5
            
            if should_award:
                user.add_badge(badge.name)
                user.add_experience(badge.points_reward)
                
                # Créer une notification
                notification = Notification(
                    user_id=user.id,
                    type='badge',
                    title='Nouveau badge obtenu !',
                    message=f'Vous avez obtenu le badge "{badge.name}" : {badge.description}',
                )
                db.session.add(notification)
                
                # Émettre une notification temps réel
                socketio.emit('notification', {
                    'type': 'badge',
                    'title': 'Nouveau badge obtenu !',
                    'message': f'Vous avez obtenu le badge "{badge.name}" : {badge.description}',
                    'user_id': user.id
                })
                
                flash(f'Félicitations ! Vous avez obtenu le badge "{badge.name}" !', 'success')


# 🔹 Route pour initialiser les badges (à appeler une seule fois)
@app.route('/init_badges')
@admin_required
def init_badges():
    create_default_badges()
    flash('Badges par défaut créés avec succès !', 'success')
    return redirect(url_for('admin_dashboard'))


# 🔹 Édition du profil utilisateur
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = ProfileEditForm(original_username=current_user.username)
    
    if form.validate_on_submit():
        # Mettre à jour le nom d'utilisateur
        current_user.username = form.username.data
        
        # Gérer l'upload de la photo de profil
        if form.profile_picture.data:
            file = form.profile_picture.data
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Create unique name to avoid conflicts
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"profile_{current_user.id}_{timestamp}_{filename}"
                file_path = os.path.join('uploads', filename)
                file.save(file_path)
                
                # Remove old photo if it exists
                if current_user.profile_picture and os.path.exists(current_user.profile_picture):
                    os.remove(current_user.profile_picture)
                
                current_user.profile_picture = file_path
            else:
                flash('File format not supported. Use JPG, PNG, GIF or JPEG.', 'danger')
                return redirect(url_for('edit_profile'))
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_profile', user_id=current_user.id))
    
    # Pré-remplir le formulaire avec les données actuelles
    form.username.data = current_user.username
    
    return render_template('edit_profile.html', form=form)


