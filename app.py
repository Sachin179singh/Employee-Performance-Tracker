import os
import hashlib
from datetime import datetime as dt
import datetime

from flask import Flask, render_template, url_for, flash, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import webview
import threading
import time
from flask_session import Session  # pip install Flask-Session
import bcrypt  # pip install bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, TimeField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///company.db'
app.config['SECRET_KEY'] = os.urandom(24)  # Important for session security!
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
db = SQLAlchemy(app)
Session(app)  # Initialize Flask-Session

# --- Database Models ---
class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)  # Store hash, not plaintext!
    role = db.Column(db.String(20), default='employee')  # 'admin' or 'employee'
    mobile_number = db.Column(db.String(20))  # New mobile_number column
    attendance = db.relationship('Attendance', backref='employee', lazy=True)
    messages_sent = db.relationship('Message', backref='sender', foreign_keys='[Message.sender_id]', lazy=True)
    messages_received = db.relationship('Message', backref='recipient', foreign_keys='[Message.recipient_id]', lazy=True)
    meetings = db.relationship('Meeting', backref='employee', lazy=True)

    def __repr__(self):
        return f"Employee('{self.name}', '{self.email}')"

    def set_password(self, password):
        """Hashes the password using bcrypt."""
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time_in = db.Column(db.Time)
    time_out = db.Column(db.Time)

    def __repr__(self):
        return f"Attendance('{self.date}', '{self.time_in}', '{self.time_out}')"

class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(100))
    description = db.Column(db.Text)

    def __repr__(self):
        return f"Meeting('{self.title}', '{self.date}')"

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=dt.now(datetime.UTC), nullable=False)
    content = db.Column(db.Text, nullable=False)

# --- Forms ---
class LoginForm(FlaskForm):
    employee_id = StringField('Employee ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class MeetingForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()])
    time = TimeField('Time', validators=[DataRequired()])
    location = StringField('Location')
    description = TextAreaField('Description')
    submit = SubmitField('Create Meeting')

class EmployeeForm(FlaskForm):
    employee_id = StringField('Employee ID', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    role = SelectField('Role', choices=[('employee', 'Employee'), ('admin', 'Admin')], validators=[DataRequired()])
    mobile_number = StringField('Mobile Number')  # New mobile_number field
    submit = SubmitField('Create Employee')

    def validate_employee_id(self, employee_id):
        employee = Employee.query.filter_by(employee_id=employee_id.data).first()
        if employee:
            raise ValidationError('That employee ID is already taken.')

    def validate_email(self, email):
        employee = Employee.query.filter_by(email=email.data).first()
        if employee:
            raise ValidationError('That email is already taken.')

class MessageForm(FlaskForm):
    content = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')

# --- Helper functions ---
def is_admin():
    """Checks if the current user is an administrator."""
    return session.get('user_role') == 'admin'

def login_required(f):
    """Decorator to require login for a route."""
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Authentication Routes ---
@app.route("/", methods=['GET', 'POST'])
@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        employee = Employee.query.filter_by(employee_id=form.employee_id.data).first()
        if employee and employee.check_password(form.password.data):
            session['user_id'] = employee.id
            session['user_role'] = employee.role
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# --- Employee Routes ---
@app.route("/profile")
#@login_required
def profile():
    employee = Employee.query.get(session['user_id'])
    # Fetch only upcoming meetings for the dashboard
    now = dt.now(datetime.UTC)
    meetings = Meeting.query.filter_by(employee_id=employee.id).filter(Meeting.date >= now).order_by(Meeting.date).limit(5).all()  # Limit to 5 upcoming meetings
    return render_template('profile.html', employee=employee, meetings=meetings)

@app.route("/attendance")
#@login_required
def attendance():
    employee = Employee.query.get(session['user_id'])
    attendances = Attendance.query.filter_by(employee_id=employee.id).all()
    return render_template('attendance.html', attendances=attendances)

@app.route("/meetings")
#@login_required
def meetings():
    employee = Employee.query.get(session['user_id'])
    meetings = Meeting.query.filter_by(employee_id=employee.id).all()
    return render_template('meetings.html', meetings=meetings)

@app.route("/inbox")
#@login_required
def inbox():
    employee = Employee.query.get(session['user_id'])
    messages = Message.query.filter(Message.recipient_id == employee.id).order_by(Message.timestamp.desc()).all()
    return render_template('inbox.html', messages=messages)

@app.route("/send_message/<int:recipient_id>", methods=['GET', 'POST'])
#@login_required
def send_message(recipient_id):
    form = MessageForm()
    recipient = Employee.query.get_or_404(recipient_id)
    if form.validate_on_submit():
        sender_id = session['user_id']
        new_message = Message(sender_id=sender_id, recipient_id=recipient_id, content=form.content.data)
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent!', 'success')
        return redirect(url_for('inbox'))

    return render_template('send_message.html', form=form, recipient=recipient)

# --- Admin Routes ---
@app.route("/admin")
#@login_required
def admin():
    if not is_admin():
        flash("You are not authorized to access this page.", "danger")
        return redirect(url_for("profile"))
    employees = Employee.query.all()
    return render_template('admin.html', employees=employees)

@app.route("/admin/employee/<int:employee_id>")
#@login_required
def view_employee_profile(employee_id):
    if not is_admin():
        flash("You are not authorized to view employee profiles.", "danger")
        return redirect(url_for("profile"))

    employee = Employee.query.get_or_404(employee_id)
    now = dt.now(datetime.UTC)
    meetings = Meeting.query.filter_by(employee_id=employee.id).filter(Meeting.date >= now).order_by(Meeting.date).limit(5).all()
    return render_template('profile.html', employee=employee, meetings=meetings)  # Reuse the profile template


@app.route("/admin/employee/new", methods=['GET', 'POST'])
#@login_required
def create_employee():
    if not is_admin():
        flash("You are not authorized to create employees.", "danger")
        return redirect(url_for("profile"))

    form = EmployeeForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        employee = Employee(employee_id=form.employee_id.data, name=form.name.data, email=form.email.data, password=hashed_password, role=form.role.data, mobile_number=form.mobile_number.data) # Included mobile number
        db.session.add(employee)
        db.session.commit()
        flash('Employee created successfully!', 'success')
        return redirect(url_for('admin'))
    return render_template('create_employee.html', form=form)

@app.route("/admin/employee/<int:employee_id>/delete", methods=['POST'])
#@login_required
def delete_employee(employee_id):
    if not is_admin():
        flash("You are not authorized to delete employees.", "danger")
        return redirect(url_for("profile"))

    employee = Employee.query.get_or_404(employee_id)
    if employee.role == 'admin' and employee.employee_id == 'admin':
        flash("You are not authorized to delete default admin.", "danger")
        return redirect(url_for("admin"))
    # Delete related messages
    Message.query.filter((Message.sender_id == employee_id) | (Message.recipient_id == employee_id)).delete()
    
    db.session.delete(employee)
    db.session.commit()
    flash('Employee deleted successfully!', 'success')
    return redirect(url_for('admin'))

@app.route("/admin/employee/<int:employee_id>/attendance", methods=['GET'])
#@login_required
def view_employee_attendance(employee_id):
    if not is_admin():
        flash("You are not authorized to view attendance.", "danger")
        return redirect(url_for("profile"))

    employee = Employee.query.get_or_404(employee_id)
    attendances = Attendance.query.filter_by(employee_id=employee.id).all()
    return render_template('employee_attendance.html', employee=employee, attendances=attendances)

@app.route("/create_meeting", methods=['GET', 'POST'])
#@login_required
def create_meeting():
    if not is_admin():
        flash("You are not authorized to create meetings.", "danger")
        return redirect(url_for("profile"))

    form = MeetingForm()
    if form.validate_on_submit():
        employee_id = session['user_id']
        combined_datetime = datetime.combine(form.date.data, form.time.data)
        new_meeting = Meeting(
            employee_id=employee_id,
            title=form.title.data,
            date=combined_datetime,
            location=form.location.data,
            description=form.description.data
        )
        db.session.add(new_meeting)
        db.session.commit()
        flash('Meeting created successfully!', 'success')
        return redirect(url_for('admin'))  # Redirect to admin or meetings page

    return render_template('create_meeting.html', form=form)


@app.route("/calendar")
def calendar():
    return render_template("calendar.html")





# --- WebView Integration ---
def start_server():
    app.run(debug=True, host='0.0.0.0', port=5000)  # Be explicit about host and port

if __name__ == '__main__':
    # --- Database setup ---
    with app.app_context():
        #db.drop_all() # ONLY UNCOMMENT THIS IF YOU WANT TO RESET THE DB, DO NOT RUN IN PRODUCTION
        db.create_all()
        # Create admin user if it doesn't exist
        admin_user = Employee.query.filter_by(employee_id='admin').first()
        if not admin_user:
            admin_user = Employee(employee_id='admin', name='Harsh Raj Jaiswal', email='admin@example.com', role='admin', mobile_number='7754938396')  # Included mobile number
            admin_user.set_password('password')  # USE A STRONG PASSWORD!
            db.session.add(admin_user)
            db.session.commit()
        start_server()

    # --- Start Flask server in a thread ---
    # t = threading.Thread(target=start_server)
    # t.daemon = True
    # t.start()
    # time.sleep(1)  # Give the server a moment to start

    # # --- Create and run WebView window ---
    # webview.create_window("Digipodium", "http://127.0.0.1:5000/",maximized=True)
    # webview.start()