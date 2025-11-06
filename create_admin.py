#!/usr/bin/env python3
"""
Script to create an admin user for TechBlog
Usage: python create_admin.py
"""

from app import create_app, db
from app.models import User
from flask_bcrypt import Bcrypt
import getpass

def create_admin():
    app = create_app()
    bcrypt = Bcrypt(app)
    
    with app.app_context():
        print("\n=== TechBlog - Create Admin User ===\n")
        
        # Check if admin already exists
        existing_admin = User.query.filter_by(is_admin=True).first()
        if existing_admin:
            print(f"⚠️  Admin user already exists: {existing_admin.username}")
            overwrite = input("Create another admin? (y/n): ").lower()
            if overwrite != 'y':
                print("Cancelled.")
                return
        
        # Get username
        while True:
            username = input("Enter admin username: ").strip()
            if len(username) < 3:
                print("❌ Username must be at least 3 characters long")
                continue
            
            # Check if username exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                print(f"❌ Username '{username}' already exists")
                continue
            break
        
        # Get password
        while True:
            password = getpass.getpass("Enter admin password: ")
            if len(password) < 6:
                print("❌ Password must be at least 6 characters long")
                continue
            
            password_confirm = getpass.getpass("Confirm password: ")
            if password != password_confirm:
                print("❌ Passwords don't match")
                continue
            break
        
        # Create admin user
        try:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            admin = User(
                username=username,
                password=hashed_password,
                is_admin=True,
                level=1,
                experience_points=0
            )
            
            db.session.add(admin)
            db.session.commit()
            
            print(f"\n✅ Admin user '{username}' created successfully!")
            print(f"\nYou can now login at: http://localhost:5000/login")
            print(f"Username: {username}")
            print("\n" + "="*50 + "\n")
            
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ Error creating admin user: {e}")

if __name__ == '__main__':
    create_admin()

