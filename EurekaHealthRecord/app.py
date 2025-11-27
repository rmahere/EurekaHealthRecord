
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory
from datetime import datetime, date as date_cls, timedelta
from pathlib import Path
import os

app = Flask(__name__)

# ---------- Database configuration ----------
ABS_DB_PATH = Path(app.root_path, "instance", "database.db").resolve()
os.makedirs(ABS_DB_PATH.parent, exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{ABS_DB_PATH.as_posix()}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "change-me"


app.config["UPLOAD_FOLDER"] = Path(app.root_path, "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB upload limit

db = SQLAlchemy(app)

# ---------- Models ----------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="patient")  # 'doctor' or 'patient'

    # One-to-one link for a patient account
    patient = db.relationship(
        "Patient",
        uselist=False,
        foreign_keys="Patient.user_id",
        backref=db.backref("user", foreign_keys="Patient.user_id"),
    )

    def set_password(self, pw: str) -> None:
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)



class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)

    # Login link (optional – a patient may exist before they register)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=True)

    # Owning doctor
    doctor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    doctor = db.relationship("User", foreign_keys=[doctor_id])

    # Iteration K – extended profile information
    phone = db.Column(db.String(50), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    allergies = db.Column(db.String(255), nullable=True)
    avatar_url = db.Column(db.String(255), nullable=True)


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    # Date and time are kept as simple strings from the form to stay beginner‑friendly
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(10), nullable=True)
    reason = db.Column(db.String(255), nullable=True)

    # Iteration I: status of the appointment request
    status = db.Column(db.String(20), nullable=False, default="Pending")  # Pending / Approved / Rejected

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    patient = db.relationship("Patient", backref="appointments")
    doctor = db.relationship("User", foreign_keys=[doctor_id])


class Medication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False)
    medication = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    patient = db.relationship("Patient", backref="medications")


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False)
    review = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    patient = db.relationship("Patient", backref="reviews")




class ActivityLog(db.Model):
    """Iteration R – simple audit trail of key actions."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(80), nullable=False)
    details = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="activity_logs")


class MedicalFile(db.Model):
    """Iteration S – uploaded medical records per appointment."""
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey("appointment.id"), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    appointment = db.relationship("Appointment", backref="files")

class Notification(db.Model):
    """Iteration J – basic in‑app notifications."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="notifications")


# ---------- Helper functions / decorators ----------

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return User.query.get(uid)


def login_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapper


def doctor_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user.role != "doctor":
            abort(403)
        return fn(*args, **kwargs)

    return wrapper


def patient_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user.role != "patient":
            abort(403)
        return fn(*args, **kwargs)

    return wrapper




def log_activity(action: str, details: str = "") -> None:
    """Create a simple audit log entry (Iteration R)."""
    try:
        uid = session.get("user_id")
        entry = ActivityLog(user_id=uid, action=action[:80], details=details[:255])
        db.session.add(entry)
        db.session.commit()
    except Exception:
        # Logging must never break the main flow.
        db.session.rollback()
def create_notification(user_id: int, message: str) -> None:
    note = Notification(user_id=user_id, message=message)
    db.session.add(note)
    db.session.commit()


def get_upcoming_appointment_reminders(user: User):
    """Iteration J – simple 'near date' reminders shown on dashboards."""
    reminders = []
    today = date_cls.today()
    soon = today + timedelta(days=2)

    if user.role == "patient" and user.patient:
        appts = Appointment.query.filter_by(patient_id=user.patient.id).all()
    elif user.role == "doctor":
        appts = Appointment.query.filter_by(doctor_id=user.id).all()
    else:
        appts = []

    for a in appts:
        try:
            appt_date = datetime.strptime(a.date, "%Y-%m-%d").date()
        except Exception:
            continue
        if today <= appt_date <= soon and a.status == "Approved":
            who = "your patient" if user.role == "doctor" else "you"
            reminders.append(f"Upcoming appointment for {who} on {a.date} at {a.time or 'time not set'}.")
    return reminders


# ---------- Auth routes ----------

@app.route("/")
def index():
    return render_template("index.html", user=current_user())


@app.route("/about")
def about():
    return render_template("about.html", user=current_user())


@app.route("/contact")
def contact():
    return render_template("contact.html", user=current_user())


@app.route("/register", methods=["GET", "POST"])

def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "patient")
        name = request.form.get("name", "").strip()

        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("register.html", user=current_user())

        if User.query.filter_by(email=email).first():
            flash("That email is already registered. Try logging in.", "error")
            return render_template("register.html", user=current_user())

        user = User(email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()  # so user.id is available

        if role == "patient":
            if not name:
                name = email.split("@")[0]
            patient = Patient(name=name, user_id=user.id)  # not linked to doctor yet
            db.session.add(patient)

        db.session.commit()
        log_activity("register", f"New user {email} as {role}")
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", user=current_user())



@app.route("/login", methods=["GET", "POST"])

def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Invalid email or password.", "error")
            log_activity("login_failed", f"Failed login for {email}")
            return render_template("login.html", user=current_user())

        session["user_id"] = user.id
        log_activity("login", f"User {email} logged in")
        flash("Logged in successfully.", "success")
        if user.role == "doctor":
            return redirect(url_for("doctor_dashboard"))
        return redirect(url_for("patient_dashboard"))

    return render_template("login.html", user=current_user())



@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


# ---------- Doctor views ----------


@app.route("/doctor")
@doctor_required
def doctor_dashboard():
    user = current_user()

    # Iteration L – simple search/filter by patient name
    search = request.args.get("q", "").strip()
    query = Patient.query.filter_by(doctor_id=user.id)
    if search:
        query = query.filter(Patient.name.ilike(f"%{search}%"))
    patients = query.order_by(Patient.name.asc()).all()

    # Pending appointment requests for Iteration I / M
    pending_appts = (
        Appointment.query.filter_by(doctor_id=user.id, status="Pending")
        .order_by(Appointment.created_at.desc())
        .all()
    )

    # Iteration N – dashboard analytics
    total_patients = Patient.query.filter_by(doctor_id=user.id).count()
    total_appointments = Appointment.query.filter_by(doctor_id=user.id).count()
    total_medications = (
        Medication.query.join(Patient).filter(Patient.doctor_id == user.id).count()
    )
    stats = {
        "patients": total_patients,
        "appointments": total_appointments,
        "pending": len(pending_appts),
        "medications": total_medications,
    }

    reminders = get_upcoming_appointment_reminders(user)
    return render_template(
        "doctor_dashboard.html",
        user=user,
        patients=patients,
        pending_appts=pending_appts,
        reminders=reminders,
        stats=stats,
        search=search,
    )


@app.route("/add_patient", methods=["GET", "POST"])
@doctor_required
def add_patient():
    user = current_user()
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("Email is required.", "error")
            return render_template("add_patient.html", user=user)

        linked_user = User.query.filter_by(email=email).first()
        if not linked_user:
            flash("Patient must register first with that email.", "error")
            return render_template("add_patient.html", user=user)

        # If there is already a Patient row for this user, reuse it
        patient = Patient.query.filter_by(user_id=linked_user.id).first()
        if patient:
            if patient.doctor_id and patient.doctor_id != user.id:
                flash("Patient is already assigned to another doctor.", "error")
                return render_template("add_patient.html", user=user)
            patient.doctor_id = user.id
            db.session.commit()
            flash("Existing patient linked to you.", "success")
            log_activity("add_patient", f"Linked existing patient {patient.id} to doctor {user.id}")
            return redirect(url_for("doctor_dashboard"))

        # Otherwise create a Patient linked to this user
        name = email.split("@")[0]
        patient = Patient(name=name, user_id=linked_user.id, doctor_id=user.id)
        db.session.add(patient)
        db.session.commit()
        flash("Patient added and linked to the registered account.", "success")
        log_activity("add_patient", f"Created patient {patient.id} for doctor {user.id}")
        return redirect(url_for("doctor_dashboard"))

    return render_template("add_patient.html", user=current_user())


@app.route("/add_visit", methods=["GET", "POST"])
@doctor_required
def add_visit():
    user = current_user()
    patients = Patient.query.filter_by(doctor_id=user.id).order_by(Patient.name.asc()).all()
    if request.method == "POST":
        try:
            patient_id = int(request.form.get("patient_id"))
        except (TypeError, ValueError):
            patient_id = None
        date_value = request.form.get("date")
        time_value = request.form.get("time")
        notes = request.form.get("notes")

        if not (patient_id and date_value and notes):
            flash("Patient, date, and notes are required.", "error")
            return render_template("add_visit.html", patients=patients, user=user)

        patient = Patient.query.get_or_404(patient_id)
        if patient.doctor_id != user.id:
            abort(403)

        # Appointment + review together (existing behaviour)
        appt = Appointment(
            patient_id=patient_id,
            doctor_id=user.id,
            date=date_value,
            time=time_value,
            reason=notes,
            status="Approved",  # Doctor is directly recording a confirmed visit
        )
        rev = Review(patient_id=patient_id, review=notes)
        db.session.add_all([appt, rev])

        # Notify patient about the new visit / appointment
        if patient.user_id:
            create_notification(
                patient.user_id,
                f"New visit recorded for {date_value} – check your dashboard for details.",
            )

        db.session.commit()
        log_activity("add_visit", f"Added visit for patient {patient_id}")
        flash("Appointment and review saved.", "success")
        return redirect(url_for("manage_patient", pid=patient_id))

    return render_template("add_visit.html", patients=patients, user=user)


@app.route("/doctor/patient/<int:pid>")
@doctor_required
def manage_patient(pid):
    user = current_user()
    patient = Patient.query.get_or_404(pid)
    if patient.doctor_id != user.id:
        abort(403)

    appts = Appointment.query.filter_by(patient_id=pid).order_by(Appointment.date.desc()).all()
    meds = Medication.query.filter_by(patient_id=pid).order_by(Medication.created_at.desc()).all()
    revs = Review.query.filter_by(patient_id=pid).order_by(Review.created_at.desc()).all()
    return render_template(
        "manage_patient.html",
        user=user,
        patient=patient,
        appointments=appts,
        medications=meds,
        reviews=revs,
    )


@app.route("/doctor/patient/<int:pid>/assign", methods=["POST"])
@doctor_required
def assign_patient(pid):
    user = current_user()
    patient = Patient.query.get_or_404(pid)
    if patient.doctor_id and patient.doctor_id != user.id:
        abort(403)
    patient.doctor_id = user.id
    db.session.commit()
    flash("Patient assigned to you.", "success")
    return redirect(url_for("manage_patient", pid=pid))


@app.route("/doctor/patient/<int:pid>/edit", methods=["GET", "POST"])
@doctor_required
def edit_patient(pid):
    user = current_user()
    patient = Patient.query.get_or_404(pid)
    if patient.doctor_id != user.id:
        abort(403)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Name is required.", "error")
            return render_template("edit_patient.html", patient=patient, user=user)
        patient.name = name
        db.session.commit()
        flash("Patient updated.", "success")
        return redirect(url_for("manage_patient", pid=patient.id))

    return render_template("edit_patient.html", patient=patient, user=user)


@app.route("/doctor/patient/<int:pid>/delete", methods=["POST"])
@doctor_required
def delete_patient(pid):
    user = current_user()
    patient = Patient.query.get_or_404(pid)
    if patient.doctor_id != user.id:
        abort(403)
    # Cascade delete simple: delete appointments, meds, reviews, then patient
    Appointment.query.filter_by(patient_id=patient.id).delete()
    Medication.query.filter_by(patient_id=patient.id).delete()
    Review.query.filter_by(patient_id=patient.id).delete()
    db.session.delete(patient)
    db.session.commit()
    flash("Patient and related records deleted.", "success")
    return redirect(url_for("doctor_dashboard"))


# ---------- Appointment management (Iteration I) ----------

@app.route("/doctor/appointment/<int:aid>/edit", methods=["GET", "POST"])
@doctor_required
def edit_appointment(aid):
    user = current_user()
    appt = Appointment.query.get_or_404(aid)
    patient = Patient.query.get_or_404(appt.patient_id)
    if patient.doctor_id != user.id:
        abort(403)

    if request.method == "POST":
        date_value = request.form.get("date")
        time_value = request.form.get("time")
        status = request.form.get("status", appt.status)
        reason = request.form.get("reason", appt.reason)

        if not date_value:
            flash("Date is required.", "error")
            return render_template("edit_appointment.html", appt=appt, user=user)

        appt.date = date_value
        appt.time = time_value
        appt.status = status
        appt.reason = reason
        db.session.commit()

        # Notifications for status change
        if patient.user_id:
            create_notification(
                patient.user_id,
                f"Your appointment on {appt.date} was updated to status '{appt.status}'.",
            )

        flash("Appointment updated.", "success")
        return redirect(url_for("manage_patient", pid=appt.patient_id))

    return render_template("edit_appointment.html", appt=appt, user=user)


@app.route("/doctor/appointment/<int:aid>/delete", methods=["POST"])
@doctor_required
def delete_appointment(aid):
    user = current_user()
    appt = Appointment.query.get_or_404(aid)
    patient = Patient.query.get_or_404(appt.patient_id)
    if patient.doctor_id != user.id:
        abort(403)
    db.session.delete(appt)
    db.session.commit()
    flash("Appointment deleted.", "success")
    return redirect(url_for("manage_patient", pid=patient.id))


@app.route("/doctor/appointment/<int:aid>/approve", methods=["POST"])
@doctor_required
def approve_appointment(aid):
    """Quick 'Approve' button for pending requests."""
    user = current_user()
    appt = Appointment.query.get_or_404(aid)
    patient = Patient.query.get_or_404(appt.patient_id)
    if patient.doctor_id != user.id:
        abort(403)

    appt.status = "Approved"
    db.session.commit()
    if patient.user_id:
        create_notification(
            patient.user_id,
            f"Your appointment request on {appt.date} was approved.",
        )
    flash("Appointment approved.", "success")
    return redirect(request.referrer or url_for("doctor_dashboard"))


@app.route("/doctor/appointment/<int:aid>/reject", methods=["POST"])
@doctor_required
def reject_appointment(aid):
    user = current_user()
    appt = Appointment.query.get_or_404(aid)
    patient = Patient.query.get_or_404(appt.patient_id)
    if patient.doctor_id != user.id:
        abort(403)

    appt.status = "Rejected"
    db.session.commit()
    if patient.user_id:
        create_notification(
            patient.user_id,
            f"Your appointment request on {appt.date} was rejected.",
        )
    flash("Appointment rejected.", "success")
    return redirect(request.referrer or url_for("doctor_dashboard"))


# ---------- Medication & review ----------

@app.route("/add_medication", methods=["GET", "POST"])
@doctor_required
def add_medication():
    user = current_user()
    patients = Patient.query.filter_by(doctor_id=user.id).order_by(Patient.name.asc()).all()
    if request.method == "POST":
        try:
            patient_id = int(request.form.get("patient_id"))
        except (TypeError, ValueError):
            patient_id = None
        medication_text = request.form.get("medication")

        if not (patient_id and medication_text):
            flash("All fields are required.", "error")
            return render_template("add_medication.html", patients=patients, user=user)

        patient = Patient.query.get_or_404(patient_id)
        if patient.doctor_id != user.id:
            abort(403)

        med = Medication(patient_id=patient_id, medication=medication_text)
        db.session.add(med)

        # Notification for new prescription
        if patient.user_id:
            create_notification(
                patient.user_id,
                f"New medication added: {medication_text}.",
            )

        db.session.commit()
        log_activity("add_medication", f"Added medication for patient {patient_id}")
        flash("Medication saved.", "success")
        return redirect(url_for("manage_patient", pid=patient_id))

    return render_template("add_medication.html", patients=patients, user=user)


@app.route("/doctor/medication/<int:mid>/edit", methods=["GET", "POST"])
@doctor_required
def edit_medication(mid):
    user = current_user()
    med = Medication.query.get_or_404(mid)
    patient = Patient.query.get_or_404(med.patient_id)
    if patient.doctor_id != user.id:
        abort(403)

    if request.method == "POST":
        medication_text = request.form.get("medication")
        if not medication_text:
            flash("Medication text is required.", "error")
            return render_template("edit_medication.html", med=med, user=user)
        med.medication = medication_text
        db.session.commit()
        flash("Medication updated.", "success")
        return redirect(url_for("manage_patient", pid=patient.id))

    return render_template("edit_medication.html", med=med, user=user)


@app.route("/doctor/medication/<int:mid>/delete", methods=["POST"])
@doctor_required
def delete_medication(mid):
    user = current_user()
    med = Medication.query.get_or_404(mid)
    patient = Patient.query.get_or_404(med.patient_id)
    if patient.doctor_id != user.id:
        abort(403)
    pid = med.patient_id
    db.session.delete(med)
    db.session.commit()
    flash("Medication deleted.", "success")
    return redirect(url_for("manage_patient", pid=pid))


@app.route("/doctor/review/<int:rid>/edit", methods=["GET", "POST"])
@doctor_required
def edit_review(rid):
    user = current_user()
    rev = Review.query.get_or_404(rid)
    patient = Patient.query.get_or_404(rev.patient_id)
    if patient.doctor_id != user.id:
        abort(403)

    if request.method == "POST":
        review_text = request.form.get("review", "").strip()
        if not review_text:
            flash("Review text is required.", "error")
            return render_template("edit_review.html", rev=rev, user=user)
        rev.review = review_text
        db.session.commit()
        flash("Review updated.", "success")
        return redirect(url_for("manage_patient", pid=rev.patient_id))

    return render_template("edit_review.html", rev=rev, user=user)


@app.route("/doctor/review/<int:rid>/delete", methods=["POST"])
@doctor_required
def delete_review(rid):
    user = current_user()
    rev = Review.query.get_or_404(rid)
    patient = Patient.query.get_or_404(rev.patient_id)
    if patient.doctor_id != user.id:
        abort(403)
    pid = rev.patient_id
    db.session.delete(rev)
    db.session.commit()
    flash("Review deleted.", "success")
    return redirect(url_for("manage_patient", pid=pid))


# ---------- Patient views / Iteration I request flow ----------


@app.route("/patient")
@patient_required
def patient_dashboard():
    user = current_user()
    if not user.patient:
        flash("No patient profile linked to this account yet.", "error")
        return redirect(url_for("index"))

    patient = user.patient
    appts = (
        Appointment.query.filter_by(patient_id=patient.id)
        .order_by(Appointment.date.desc())
        .all()
    )
    meds = (
        Medication.query.filter_by(patient_id=patient.id)
        .order_by(Medication.created_at.desc())
        .all()
    )
    revs = (
        Review.query.filter_by(patient_id=patient.id)
        .order_by(Review.created_at.desc())
        .all()
    )

    # Iteration N – simple stats for the patient
    stats = {
        "appointments": len(appts),
        "medications": len(meds),
        "reviews": len(revs),
    }

    reminders = get_upcoming_appointment_reminders(user)
    return render_template(
        "patient_dashboard.html",
        user=user,
        patient=patient,
        appointments=appts,
        medications=meds,
        reviews=revs,
        reminders=reminders,
        stats=stats,
    )


@app.route("/patient/appointments/request", methods=["GET", "POST"])
@patient_required
def request_appointment():
    """Iteration I – patient requests an appointment which the doctor can approve/reject."""
    user = current_user()
    patient = user.patient
    if not patient or not patient.doctor_id:
        flash("You must be assigned to a doctor before requesting an appointment.", "error")
        return redirect(url_for("patient_dashboard"))

    if request.method == "POST":
        date_value = request.form.get("date")
        time_value = request.form.get("time")
        reason = request.form.get("reason", "").strip()

        if not (date_value and time_value and reason):
            flash("Date, time, and reason are required.", "error")
            return render_template("request_appointment.html", user=user, patient=patient)

        appt = Appointment(
            patient_id=patient.id,
            doctor_id=patient.doctor_id,
            date=date_value,
            time=time_value,
            reason=reason,
            status="Pending",
        )
        db.session.add(appt)
        db.session.commit()
        log_activity("request_appointment", f"Patient {patient.id} requested appointment on {date_value}")

        # Notify doctor that a new request has arrived
        create_notification(
            patient.doctor_id,
            f"New appointment request from {patient.name} on {date_value} at {time_value}.",
        )

        flash("Appointment request submitted as Pending.", "success")
        return redirect(url_for("patient_dashboard"))

    return render_template("request_appointment.html", user=user, patient=patient)


# ---------- Notifications (Iteration J) ----------

@app.route("/notifications")
@login_required
def notifications():
    user = current_user()
    notes = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).all()
    return render_template("notifications.html", user=user, notifications=notes)




# ---------- Patient profile (Iteration K) ----------

@app.route("/patient/profile", methods=["GET", "POST"])
@patient_required
def patient_profile():
    user = current_user()
    patient = user.patient
    if not patient:
        flash("No patient profile linked to this account yet.", "error")
        return redirect(url_for("patient_dashboard"))

    if request.method == "POST":
        patient.phone = request.form.get("phone", "").strip() or None
        patient.address = request.form.get("address", "").strip() or None
        patient.allergies = request.form.get("allergies", "").strip() or None
        db.session.commit()
        log_activity("patient_profile_update", f"Updated profile for patient {patient.id}")
        flash("Profile updated successfully.", "success")
        return redirect(url_for("patient_profile"))

    return render_template("patient_profile.html", user=user, patient=patient)


# ---------- Export / reporting (Iteration O) ----------

import csv
from io import StringIO
from flask import Response

@app.route("/doctor/export")
@doctor_required
def doctor_export():
    """Export appointments or medications as CSV."""
    kind = request.args.get("kind", "appointments")
    user = current_user()

    si = StringIO()
    writer = csv.writer(si)

    if kind == "medications":
        meds = Medication.query.join(Patient).filter(Patient.doctor_id == user.id).all()
        writer.writerow(["Patient", "Medication", "Created at"])
        for m in meds:
            writer.writerow([m.patient.name, m.medication, m.created_at.strftime("%Y-%m-%d")])
        filename = "medications.csv"
    else:
        # default: appointments
        appts = Appointment.query.join(Patient).filter(Patient.doctor_id == user.id).all()
        writer.writerow(["Patient", "Date", "Time", "Status", "Reason"])
        for a in appts:
            writer.writerow([a.patient.name, a.date, a.time or "", a.status, a.reason or ""])
        filename = "appointments.csv"

    output = si.getvalue()
    log_activity("export", f"Exported {kind} CSV")
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"},
    )


# ---------- Password reset (Iteration P) ----------

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        new_pw = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not email or not new_pw or not confirm:
            flash("All fields are required.", "error")
            return render_template("forgot_password.html", user=current_user())

        if new_pw != confirm:
            flash("Passwords do not match.", "error")
            return render_template("forgot_password.html", user=current_user())

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with that email.", "error")
            return render_template("forgot_password.html", user=current_user())

        user.set_password(new_pw)
        db.session.commit()
        log_activity("password_reset", f"Password reset for {email}")
        flash("Password reset successful. Please log in with your new password.", "success")
        return redirect(url_for("login"))

    return render_template("forgot_password.html", user=current_user())


# ---------- File upload for medical records (Iteration S) ----------

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "doc", "docx"}

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/doctor/appointment/<int:aid>/upload", methods=["GET", "POST"])
@doctor_required
def upload_record(aid):
    user = current_user()
    appt = Appointment.query.get_or_404(aid)
    patient = Patient.query.get_or_404(appt.patient_id)
    if patient.doctor_id != user.id:
        abort(403)

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            flash("Please choose a file.", "error")
            return render_template("upload_record.html", user=user, appt=appt)

        if not allowed_file(file.filename):
            flash("Unsupported file type. Please upload PDF or image.", "error")
            return render_template("upload_record.html", user=user, appt=appt)

        safe_name = secure_filename(file.filename)
        stored_name = f"{aid}_{int(datetime.utcnow().timestamp())}_{safe_name}"
        save_path = app.config["UPLOAD_FOLDER"] / stored_name
        file.save(save_path)

        rec = MedicalFile(
            appointment_id=aid,
            stored_name=stored_name,
            original_name=file.filename,
        )
        db.session.add(rec)
        db.session.commit()
        log_activity("upload_record", f"Uploaded {file.filename} for appointment {aid}")
        flash("File uploaded successfully.", "success")
        return redirect(url_for("manage_patient", pid=patient.id))

    return render_template("upload_record.html", user=user, appt=appt)


@app.route("/records/<int:file_id>")
@login_required
def download_record(file_id):
    mf = MedicalFile.query.get_or_404(file_id)
    appt = mf.appointment
    patient = appt.patient
    user = current_user()

    # Check access: doctor for this patient, or the patient themselves
    allowed = False
    if user.role == "doctor" and patient.doctor_id == user.id:
        allowed = True
    if user.role == "patient" and user.patient and user.patient.id == patient.id:
        allowed = True

    if not allowed:
        abort(403)

    path = app.config["UPLOAD_FOLDER"]
    return send_from_directory(path, mf.stored_name, as_attachment=True, download_name=mf.original_name)


# ---------- Activity log viewer (Iteration R) ----------

@app.route("/admin/logs")
@doctor_required
def admin_logs():
    logs = ActivityLog.query.order_by(ActivityLog.created_at.desc()).limit(200).all()
    return render_template("admin_logs.html", user=current_user(), logs=logs)

# ---------- Simple database initialisation ----------

def init_db_with_seed():
    """Create tables and add one demo doctor + patient if database is empty."""
    db.create_all()
    if not User.query.first():
        doctor = User(email="doctor@example.com", role="doctor")
        doctor.set_password("password123")
        patient_user = User(email="patient@example.com", role="patient")
        patient_user.set_password("password123")

        db.session.add_all([doctor, patient_user])
        db.session.flush()

        pat = Patient(name="John Patient", user_id=patient_user.id, doctor_id=doctor.id)
        db.session.add(pat)
        db.session.flush()

        demo_appt = Appointment(
            patient_id=pat.id,
            doctor_id=doctor.id,
            date=datetime.today().strftime("%Y-%m-%d"),
            time="10:00",
            reason="Initial check‑up",
            status="Approved",
        )
        demo_med = Medication(patient_id=pat.id, medication="Amoxicillin 500mg")
        demo_rev = Review(patient_id=pat.id, review="Follow‑up in 2 weeks.")
        db.session.add_all([demo_appt, demo_med, demo_rev])

        db.session.commit()



with app.app_context():
    # For this student demo we always recreate a fresh database
    # so that the schema matches the models and we avoid migration errors.
    if ABS_DB_PATH.exists():
        try:
            ABS_DB_PATH.unlink()
        except Exception:
            # If the file is locked for some reason we continue;
            # SQLite will still open it if possible.
            pass
    db.create_all()
    init_db_with_seed()


if __name__ == "__main__":
    # For local testing
    app.run(debug=True)
