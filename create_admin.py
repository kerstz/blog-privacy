#!/usr/bin/env python3
"""
Script to create an admin user for TechBlog
Usage: python create_admin.py
"""

from app import app, db, bcrypt
from app.models import User
import getpass
import re

def create_admin():
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
            if not re.fullmatch(r'[A-Za-z0-9_.-]{3,20}', username):
                print("❌ Username: 3-20 characters, letters/digits/_ . - only")
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
            if len(password) < 12 or len(password.encode('utf-8')) > 72:
                print("❌ Password must be 12 to 72 characters long")
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
            print("\nYou can now log in at: http://localhost:5000/login")
            print(f"Username: {username}")
            print("\n" + "="*50 + "\n")
            
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ Error creating admin user: {e}")

if __name__ == '__main__':
    create_admin()

