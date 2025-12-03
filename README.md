# Eureka Health Record (EurekaHR)

Eureka Health Record is a small-clinic web application that lets doctors and patients share a simple digital health record.
This project is a **prototype** that can grow into a larger EHR system. It focuses on a clean workflow between doctors and patients rather than covering every hospital feature.

## Features

-Doctor and patient registration and login
- Doctor links a registered patient by email
- Patients request appointments with their doctor
- Doctors approve or reject appointment requests
- Visit notes and medication history for each patient
- Upload and download medical files (reports, images, etc.)
- Role-based dashboards for doctor and patient
- Simple activity log and basic summary cards

## Tech Stack

- Python, Flask, Jinja2
- SQLite database
- HTML, CSS (custom responsive layout)
- Basic role-based access control and form validation

## Project Goals

- Act as a learning project for full-stack web development
- Provide a prototype that could later be expanded with:
  - Lab results and imaging
  - Billing and insurance modules
  - Multi-clinic support
  - Mobile apps and external APIs

## Running the Project (Windows, local)

```bash
# 1. Create virtual environment
python -m venv venv
venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Initialize database (if your project has this file)
python init_db.py

# 4. python -m pytest


# 5. Run the app
flask run
# or
python app.py
