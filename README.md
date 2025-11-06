# TechBlog

A modern, feature-rich blogging platform built with Flask. TechBlog offers a clean and responsive interface for sharing articles, engaging with readers, and building a community around technology and programming.

## Features

- **Modern UI**: Clean, responsive design with a beautiful green/orange color scheme
- **User Authentication**: Secure registration and login system
- **Article Management**: Create, edit, and publish articles with rich text editor
- **Comments System**: Nested comment threads with replies
- **Like System**: Users can like posts and comments
- **User Profiles**: Customizable user profiles with experience points and badges
- **Admin Panel**: Comprehensive dashboard for managing content and users
- **Notifications**: Real-time notification system for user interactions
- **Chat System**: Built-in messaging between users
- **Static Pages**: Create custom pages (About, Contact, etc.)
- **Responsive Design**: Fully mobile-friendly interface

## Tech Stack

- **Backend**: Flask (Python)
- **Database**: SQLAlchemy with SQLite
- **Authentication**: Flask-Login
- **Forms**: Flask-WTF
- **Real-time**: Flask-SocketIO
- **Frontend**: HTML5, CSS3, JavaScript
- **Styling**: Custom CSS with modern gradients and animations

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/techblog.git
cd techblog
```

2. **Create a virtual environment**
```bash
python -m venv venv
```

3. **Activate the virtual environment**
   - On Windows:
   ```bash
   venv\Scripts\activate
   ```
   - On macOS/Linux:
   ```bash
   source venv/bin/activate
   ```

4. **Install dependencies**
```bash
pip install -r requirements.txt
```

5. **Set up environment variables** (optional)
```bash
export SECRET_KEY='your-secret-key-here'
export DATABASE_URL='sqlite:///instance/blog.db'
```

6. **Initialize the database**
```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

7. **Run the application**
```bash
python wsgi.py
```

The application will be available at `http://localhost:5000`

## Configuration

Edit `config.py` to customize:
- Secret key
- Database URI
- Session configuration
- Cookie settings

## Project Structure

```
techblog/
├── app/
│   ├── __init__.py
│   ├── models.py          # Database models
│   ├── routes.py          # Application routes
│   ├── forms.py           # Form definitions
│   ├── utils.py           # Utility functions
│   ├── encryption.py      # Encryption utilities
│   ├── chat.py            # Chat functionality
│   ├── static/
│   │   └── css/
│   │       ├── style.css  # Main stylesheet
│   │       └── icons.css  # Icon fonts
│   └── templates/         # HTML templates
├── migrations/            # Database migrations
├── instance/             # Instance-specific files
├── config.py             # Configuration
├── wsgi.py              # Application entry point
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## Usage

### Creating an Admin User

To create an admin user, you can use the Python shell:

```bash
flask shell
```

```python
from app import db
from app.models import User
from flask_bcrypt import generate_password_hash

admin = User(
    username='admin',
    password=generate_password_hash('your_password').decode('utf-8'),
    is_admin=True
)
db.session.add(admin)
db.session.commit()
```

### Admin Panel

Access the admin panel at `/admin` with admin credentials. Features include:
- Manage posts
- Manage users
- Manage comments
- View statistics
- Manage banners
- Create static pages
- Admin chat

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is open source and available under the MIT License.

## Security

- Passwords are hashed using bcrypt
- CSRF protection enabled
- Secure session cookies
- SQL injection prevention through SQLAlchemy ORM
- Message encryption for chat system

## Future Enhancements

- [ ] Search functionality
- [ ] Categories and tags
- [ ] RSS feed
- [ ] Email notifications
- [ ] OAuth integration
- [ ] Image upload and management
- [ ] Markdown support
- [ ] SEO optimization
- [ ] Multi-language support

## Support

For issues, questions, or contributions, please open an issue on GitHub.

## Acknowledgments

Built with Flask and modern web technologies for a seamless blogging experience.

