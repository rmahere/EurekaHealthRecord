
from app import db, User, Patient

def register_user(client, email, password, role="patient", name="Test Patient"):
    return client.post(
        "/register",
        data={
            "email": email,
            "password": password,
            "role": role,
            "name": name,
        },
        follow_redirects=True,
    )

def login_user(client, email, password):
    return client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=True,
    )

def test_index_page_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Eureka Health Record" in resp.data

def test_patient_registration_and_dashboard(app, client):
    email = "patient1@example.com"
    password = "TestPass123"

    resp = register_user(
        client,
        email=email,
        password=password,
        role="patient",
        name="Patient One",
    )
    assert resp.status_code == 200
    assert b"Registration successful" in resp.data

    # Patient should exist in the database
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        assert user is not None
        assert user.role == "patient"
        assert user.patient is not None

    # Patient should be able to log in and see the dashboard
    resp = login_user(client, email, password)
    assert resp.status_code == 200
    assert b"Patient Dashboard" in resp.data

def test_doctor_registration_and_dashboard(app, client):
    email = "dr.smith@eureka.ac.zw"
    password = "TestPass123"

    resp = register_user(
        client,
        email=email,
        password=password,
        role="doctor",
        name="",
    )
    assert resp.status_code == 200
    assert b"Registration successful" in resp.data

    # Doctor should exist in the database
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        assert user is not None
        assert user.role == "doctor"

    # Doctor should be able to log in and see the doctor dashboard
    resp = login_user(client, email, password)
    assert resp.status_code == 200
    assert b"Doctor Dashboard" in resp.data

def test_doctor_route_requires_doctor_role(client):
    # Without logging in, this should be forbidden by doctor_required
    resp = client.get("/doctor")
    assert resp.status_code == 403

def test_add_patient_links_existing_patient(app, client):
    doctor_email = "dr.jones@eureka.ac.zw"
    patient_email = "patient2@example.com"
    password = "TestPass123"

    # Create doctor and patient user accounts directly in the database
    with app.app_context():
        doctor = User(email=doctor_email, role="doctor")
        doctor.set_password(password)
        db.session.add(doctor)

        patient_user = User(email=patient_email, role="patient")
        patient_user.set_password(password)
        db.session.add(patient_user)
        db.session.flush()

        patient = Patient(name="Patient Two", user_id=patient_user.id)
        db.session.add(patient)
        db.session.commit()

        doctor_id = doctor.id
        patient_user_id = patient_user.id

    # Log in as the doctor
    resp = login_user(client, doctor_email, password)
    assert resp.status_code == 200
    assert b"Doctor Dashboard" in resp.data

    # Use the Add Patient to link the already registered patient
    resp = client.post(
        "/add_patient",
        data={"email": patient_email},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    # Check for either message since the patient already exists
    assert (
        b"Existing patient linked to you." in resp.data
        or b"Patient added and linked to the registered account." in resp.data
    )

    # The patient should now be linked to the doctor
    with app.app_context():
        patient = Patient.query.filter_by(user_id=patient_user_id).first()
        assert patient is not None
        assert patient.doctor_id == doctor_id
