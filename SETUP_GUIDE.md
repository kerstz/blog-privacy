# 🚀 Quick Setup Guide for TechBlog

This guide will help you personalize your TechBlog installation in 5 minutes!

## Step 1: Change the Blog Name

Replace "TechBlog" with your blog name throughout the codebase:

### Method 1: Manual Search & Replace
1. Open your text editor (VS Code, Sublime, etc.)
2. Use "Find & Replace All" (Ctrl+Shift+H or Cmd+Shift+H)
3. Find: `TechBlog`
4. Replace: `YourBlogName`
5. Click "Replace All"

### Method 2: Command Line
```bash
# On Linux/Mac
cd /home/lorenzo/Bureau/blog_git
find . -type f -name "*.html" -o -name "*.md" | xargs sed -i 's/TechBlog/YourBlogName/g'

# On Mac (slightly different)
find . -type f -name "*.html" -o -name "*.md" | xargs sed -i '' 's/TechBlog/YourBlogName/g'
```

**Files to check:**
- `app/templates/layout.html` (navbar & title)
- `app/templates/index.html` (hero section)
- `app/templates/about.html` (page title)
- `app/templates/admin_dashboard.html` (admin panel)
- `README.md` (project title)
- `CUSTOMIZE_THEME.md` (references)

## Step 2: Add Your GitHub Link

In `app/templates/layout.html`, update the footer:

```html
<!-- Find this line (near the bottom) -->
<a href="https://github.com/yourusername/techblog" target="_blank">

<!-- Replace with YOUR repository -->
<a href="https://github.com/YOUR_USERNAME/YOUR_REPO" target="_blank">
```

**Example:**
```html
<a href="https://github.com/john-doe/my-awesome-blog" target="_blank">
```

## Step 3: Customize Colors (Optional)

Open `app/static/css/style.css` and change the first few lines:

```css
/* Find these at the top of the file */
--primary-color: #10b981;      /* Main green color */
--secondary-color: #059669;    /* Darker green */
--accent-color: #f59e0b;       /* Orange accent */

/* Change to your preferred colors */
--primary-color: #YOUR_COLOR_1;
--secondary-color: #YOUR_COLOR_2;
--accent-color: #YOUR_COLOR_3;
```

**Need help choosing colors?** See [CUSTOMIZE_THEME.md](CUSTOMIZE_THEME.md) for pre-made palettes!

## Step 4: Configure Donation Options

### Option A: Use Your Crypto Addresses

Edit `app/templates/donate.html` and update the wallet addresses with yours.

### Option B: Use External Services

Replace the donate button in `app/templates/layout.html`:

```html
<!-- Ko-fi -->
<a href="https://ko-fi.com/yourusername" class="donate-btn" target="_blank">
    ☕ Ko-fi
</a>

<!-- PayPal -->
<a href="https://paypal.me/yourusername" class="donate-btn" target="_blank">
    💳 PayPal
</a>
```

### Option C: Remove Donations

Simply delete the donate button section from `layout.html`:
```html
<!-- Remove these lines -->
<div class="footer-container">
    <a href="{{ url_for('donate') }}" class="donate-btn">
        ❤️ Support
    </a>
</div>
```

## Step 5: Create Your Admin Account

```bash
# Activate virtual environment
source venv/bin/activate

# Run the admin creation script
python create_admin.py

# Follow the prompts to set username and password
```

## Step 6: Push to GitHub

```bash
# Initialize if not already done
git init
git add .
git commit -m "Initial commit: Customized TechBlog"

# Create a new repo on GitHub, then:
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git branch -M main
git push -u origin main
```

## Quick Checklist ✅

Before going live, make sure you've:

- [ ] Changed "TechBlog" to your blog name
- [ ] Updated GitHub link in footer with your repository
- [ ] Customized colors (optional)
- [ ] Configured donation options
- [ ] Created an admin account
- [ ] Changed the secret key in `config.py`
- [ ] Updated About page with your information
- [ ] Tested the site locally with `flask run`
- [ ] Committed and pushed to GitHub

## Need More Help?

- **Theme Customization**: See [CUSTOMIZE_THEME.md](CUSTOMIZE_THEME.md)
- **Full Documentation**: See [README.md](README.md)
- **Issues**: Open an issue on GitHub

---

**Time to complete:** ~5 minutes ⚡
**Difficulty:** Beginner-friendly 🎓

Enjoy your new blog! 🎉

