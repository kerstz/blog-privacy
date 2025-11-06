# 🎨 Theme Customization Guide

TechBlog uses a modern CSS design that can be easily customized to match your personal style. Here's how to customize the theme colors and appearance.

## Quick Color Changes

The main theme uses CSS variables defined at the top of `/app/static/css/style.css`. You can easily change the entire look by modifying these values:

### Current Color Scheme (Green & Orange)

```css
:root {
    --primary-color: #10b981;      /* Emerald Green */
    --secondary-color: #059669;    /* Dark Green */
    --accent-color: #f59e0b;       /* Orange */
}
```

### Alternative Color Schemes

#### 🔵 Blue & Purple
```css
:root {
    --primary-color: #3b82f6;      /* Blue */
    --secondary-color: #6366f1;    /* Indigo */
    --accent-color: #a855f7;       /* Purple */
}
```

#### 🔴 Red & Pink
```css
:root {
    --primary-color: #ef4444;      /* Red */
    --secondary-color: #dc2626;    /* Dark Red */
    --accent-color: #ec4899;       /* Pink */
}
```

#### 🟣 Purple & Magenta
```css
:root {
    --primary-color: #8b5cf6;      /* Purple */
    --secondary-color: #7c3aed;    /* Dark Purple */
    --accent-color: #d946ef;       /* Magenta */
}
```

#### 🟡 Yellow & Orange
```css
:root {
    --primary-color: #f59e0b;      /* Amber */
    --secondary-color: #d97706;    /* Orange */
    --accent-color: #eab308;       /* Yellow */
}
```

#### ⚪ Monochrome (Black & White)
```css
:root {
    --primary-color: #ffffff;      /* White */
    --secondary-color: #e5e7eb;    /* Light Gray */
    --accent-color: #6b7280;       /* Gray */
}
```

## How to Apply Changes

1. **Open the CSS file:**
   ```bash
   nano app/static/css/style.css
   ```
   or use your preferred text editor

2. **Find the color variables** at the top of the file (around line 1-30)

3. **Replace the hex color codes** with your chosen colors

4. **Save the file** and refresh your browser

5. **No restart needed!** Changes apply immediately

## Advanced Customization

### Changing Background Gradients

Find the `body` section and modify the gradient:

```css
body {
    background: linear-gradient(135deg, #YOUR_COLOR_1 0%, #YOUR_COLOR_2 50%, #YOUR_COLOR_3 100%);
}
```

### Modifying Button Styles

Search for `.btn-modern`, `.cta-button`, or similar classes and adjust:

```css
.btn-modern {
    background: linear-gradient(135deg, #YOUR_PRIMARY 0%, #YOUR_SECONDARY 100%);
    border-radius: 10px;  /* Adjust roundness */
    padding: 12px 24px;   /* Adjust size */
}
```

### Changing Card Appearance

Modify `.stat-card`, `.action-card`, `.blog-post` classes:

```css
.blog-post {
    background: rgba(255, 255, 255, 0.05);  /* Transparency */
    border-radius: 20px;                     /* Corner roundness */
    border: 2px solid YOUR_COLOR;            /* Border color */
}
```

## AI Prompt for Custom Themes

If you want AI to help you create a completely custom theme, use this prompt:

---

**Prompt for AI (ChatGPT, Claude, etc.):**

```
I'm using TechBlog and want to customize the CSS theme. Please provide me with:

1. A complete color palette (primary, secondary, accent colors) based on [DESCRIBE YOUR PREFERRED STYLE: e.g., "cyberpunk neon", "minimalist pastel", "dark gaming theme", "professional corporate"]

2. The exact CSS color codes in hex format

3. Any additional styling suggestions (gradients, shadows, animations) that would complement this theme

4. Optional: Background image or pattern suggestions

Current structure uses:
- CSS variables for colors
- Linear gradients for backgrounds
- Border-radius for rounded corners
- Box-shadows for depth
- Transitions for smooth animations

Please format the response as copy-paste ready CSS code.
```

---

## Changing the Blog Name

To change "TechBlog" to your own blog name:

### 1. In Templates (HTML files)

**Main Layout** - `app/templates/layout.html`:
```html
<!-- Find and replace -->
<a class="navbar-brand" href="{{ url_for('index') }}">TechBlog</a>
<!-- With -->
<a class="navbar-brand" href="{{ url_for('index') }}">YourBlogName</a>
```

**Page Titles** - Same file:
```html
<title>{% block title %}TechBlog{% endblock %}</title>
<!-- Change to -->
<title>{% block title %}YourBlogName{% endblock %}</title>
```

### 2. In Other Files

**Index Page** - `app/templates/index.html`:
```html
<h1>Welcome to TechBlog</h1>
<!-- Change to -->
<h1>Welcome to YourBlogName</h1>
```

**About Page** - `app/templates/about.html`:
```html
<h1 class="about-title">🌐 About TechBlog</h1>
<!-- Change to -->
<h1 class="about-title">🌐 About YourBlogName</h1>
```

**Admin Dashboard** - `app/templates/admin_dashboard.html`:
```html
<title>Admin Panel - TechBlog</title>
<!-- Change to -->
<title>Admin Panel - YourBlogName</title>
```

**README.md**:
```markdown
# TechBlog
<!-- Change to -->
# YourBlogName
```

**Quick Search & Replace:**
```bash
# Use your text editor's "Find & Replace All" feature
# Find: TechBlog
# Replace: YourBlogName
```

## Customizing the Donation Section

The donation button appears in the footer of every page. Here's how to customize it:

### 1. Change Button Text

In `app/templates/layout.html`, find:
```html
<a href="{{ url_for('donate') }}" class="donate-btn">
    ❤️ Support
</a>
```

Change to:
```html
<a href="{{ url_for('donate') }}" class="donate-btn">
    ☕ Buy Me a Coffee
</a>
<!-- Or -->
<a href="{{ url_for('donate') }}" class="donate-btn">
    💝 Donate
</a>
<!-- Or -->
<a href="{{ url_for('donate') }}" class="donate-btn">
    🎁 Support This Blog
</a>
```

### 2. Modify Donation Page Content

Edit `app/templates/donate.html` to customize:
- **Page title**: Change the `<h1>` content
- **Description**: Update the text explaining why you need donations
- **Cryptocurrency addresses**: Update with your own wallet addresses
- **Payment methods**: Add PayPal, Ko-fi, Buy Me a Coffee links

Example in `donate.html`:
```html
<h1 class="donate-title">Support My Work</h1>
<p class="donate-description">
    Your custom message here explaining what the donations will be used for.
</p>
```

### 3. Change Donation Button Style

In `app/static/css/style.css`, find `.donate-btn`:
```css
.donate-btn {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
    /* Change colors to match your theme */
    background: linear-gradient(135deg, #YOUR_COLOR_1 0%, #YOUR_COLOR_2 100%);
}
```

### 4. Remove Donation Section

To completely remove the donation button, delete this from `layout.html`:
```html
<div class="footer-container">
    <a href="{{ url_for('donate') }}" class="donate-btn">
        ❤️ Support
    </a>
</div>
```

### 5. Add External Donation Links

Replace the donation route with external services:
```html
<!-- Ko-fi -->
<a href="https://ko-fi.com/yourusername" class="donate-btn" target="_blank">
    ☕ Ko-fi
</a>

<!-- Buy Me a Coffee -->
<a href="https://www.buymeacoffee.com/yourusername" class="donate-btn" target="_blank">
    ☕ Buy Me a Coffee
</a>

<!-- PayPal -->
<a href="https://paypal.me/yourusername" class="donate-btn" target="_blank">
    💳 PayPal
</a>
```

## Pro Tips

1. **Use a Color Picker Tool:** Try [Coolors.co](https://coolors.co) or [ColorHunt](https://colorhunt.co) for inspiration

2. **Test Contrast:** Ensure text is readable on backgrounds using [WebAIM Contrast Checker](https://webaim.org/resources/contrastchecker/)

3. **Keep it Consistent:** Use your primary color for main actions, secondary for hover states, and accent for highlights

4. **Backup First:** Before making changes, copy `style.css` to `style.css.backup`

5. **Browser DevTools:** Use F12 in your browser to test colors live before saving changes

## Example: Creating a "Midnight Blue" Theme

Replace the current colors with:

```css
body {
    background: linear-gradient(135deg, #0a1929 0%, #1a2332 50%, #0f1f3a 100%);
}

:root {
    --primary-color: #2196f3;      /* Sky Blue */
    --secondary-color: #1976d2;    /* Deep Blue */
    --accent-color: #64b5f6;       /* Light Blue */
    --dark-bg: #0a1929;
    --card-bg: #1a2332;
    --text-primary: #e3f2fd;
}
```

This will give you a cool, professional dark blue theme!

## Need Help?

- Check the official CSS documentation: [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/CSS)
- For gradient generators: [CSS Gradient](https://cssgradient.io/)
- For inspiration: [Dribble](https://dribbble.com/) or [Behance](https://www.behance.net/)

## Adding Your GitHub Link to Footer

The footer now includes a GitHub link. To update it with your repository:

### Update in `app/templates/layout.html`:

Find this line in the footer:
```html
<a href="https://github.com/yourusername/techblog" target="_blank" rel="noopener noreferrer">
```

Replace with your GitHub repository URL:
```html
<a href="https://github.com/YOUR_USERNAME/YOUR_REPO_NAME" target="_blank" rel="noopener noreferrer">
```

### Customize the Link Style:

You can change:
- **Text**: "View on GitHub" → "Star on GitHub" or "Check the Source Code"
- **Icon**: Change the ⭐ emoji to any other: 🔗 📦 💻 🚀
- **Color**: Change `color: #10b981` to any hex color

Example variations:
```html
<!-- Minimal -->
<a href="https://github.com/your/repo">GitHub</a>

<!-- With icon -->
<a href="https://github.com/your/repo">🔗 Source Code</a>

<!-- Call to action -->
<a href="https://github.com/your/repo">⭐ Star this project</a>
```

Happy customizing! 🎨✨

