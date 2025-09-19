# Student Complaint System (Flask + SQLite)

## Overview
A simple student complaint management system built with Flask and SQLite. Designed pages use Bootstrap (via CDN) for a clean, responsive UI.

## Default users
- Admin: username `admin`, password `admin123`
- Technician 1: username `tech1`, password `tech123`
- Technician 2: username `tech2`, password `tech123`

Students can register using their registration number as username and any password.

## How to run
1. Create a virtualenv and install requirements:
```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
2. Initialize database (creates admin & technicians):
```
python db_init.py
```
3. Run the app:
```
python app.py
```
4. Open `http://127.0.0.1:5000` in your browser.

## Features
- Role-selecting login (admin, technician, student accounts are by role)
- Student can register, submit complaints (category, location, description)
- Admin can view complaint list and assign a technician
- Technician can update status (Pending, In Progress, Solved, Resolved)
- When a complaint is marked Solved/Resolved, a notification is created for the student to confirm
- Logout option present on top-right of every dashboard
