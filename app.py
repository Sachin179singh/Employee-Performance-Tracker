import os
import mimetypes
from werkzeug.utils import secure_filename
import hashlib
from datetime import datetime as dt
import datetime
from flask import Flask, render_template, url_for, flash, redirect, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import webview
import threading
import time
import bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, TimeField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///company.db'
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max file size

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return Employee.query.get(int(user_id))

# Make employee data available to all templates
@app.context_processor
def inject_employee():
    def get_all_employees():
        return Employee.query.filter(Employee.id != current_user.id).all() if current_user.is_authenticated else []
    return dict(
        employee=current_user if current_user.is_authenticated else None,
        get_all_employees=get_all_employees
    )

# --- Models ---

class Employee(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)  # Store hash, not plaintext!
    role = db.Column(db.String(20), default='employee')  # 'admin' or 'employee'
    mobile_number = db.Column(db.String(20))  # New mobile_number column
    profile_picture = db.Column(db.String(120), default='default.jpg')  # Profile picture filename
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

    def is_admin(self):
        """Helper method to check if user is admin"""
        return self.role == 'admin'


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
    read = db.Column(db.Boolean, default=False)
    deleted_by_sender = db.Column(db.Boolean, default=False)
    deleted_by_recipient = db.Column(db.Boolean, default=False)

class MessageReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    emoji = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, default=dt.now(datetime.UTC), nullable=False)

    message = db.relationship('Message', backref=db.backref('reactions', lazy='dynamic'))
    user = db.relationship('Employee', backref='message_reactions')

class MessageAttachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.Integer)  # Size in bytes
    timestamp = db.Column(db.DateTime, default=dt.now(datetime.UTC), nullable=False)

    message = db.relationship('Message', backref='attachments')

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
    submit = SubmitField('Send')

# --- Helper functions ---


def allowed_file(filename):
    """Check if the file extension is allowed."""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

ALLOWED_MIME_TYPES = {
    # Images
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/gif': '.gif',
    # Documents
    'application/pdf': '.pdf',
    'application/msword': '.doc',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
    'application/vnd.ms-excel': '.xls',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
    'text/plain': '.txt'
}

def validate_file_mime_type(file):
    """Validate file MIME type and return appropriate extension if valid."""
    try:
        import magic
        mime_type = magic.from_buffer(file.read(2048), mime=True)
        file.seek(0)  # Reset file pointer after reading
        
        if mime_type in ALLOWED_MIME_TYPES:
            return ALLOWED_MIME_TYPES[mime_type]
        return None
    except ImportError:
        # Fallback to checking file extension if python-magic is not available
        filename = file.filename.lower()
        for mime_type, ext in ALLOWED_MIME_TYPES.items():
            if filename.endswith(ext):
                return ext
        return None

def is_admin():
    """Checks if the current user is an administrator."""
    return current_user.is_authenticated and current_user.role == 'admin'


# --- Authentication Routes ---


@app.route("/", methods=['GET', 'POST'])
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    form = LoginForm()
    if form.validate_on_submit():
        employee = Employee.query.filter_by(employee_id=form.employee_id.data).first()
        if employee and employee.check_password(form.password.data):
            login_user(employee)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('profile'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')
    return render_template('login.html', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# --- Employee Routes ---


@app.route("/profile")
@login_required
def profile():
    # Get current month and year
    today = dt.now(datetime.UTC)
    month_year = today.strftime('%B %Y')
    
    # Calculate calendar days for current month
    calendar_days = []
    first_day = today.replace(day=1)
    last_day = (first_day.replace(month=first_day.month % 12 + 1, day=1) - datetime.timedelta(days=1))
    
    # Get all attendance records for current month
    month_attendance = Attendance.query.filter(
        Attendance.employee_id == current_user.id,
        Attendance.date >= first_day.date(),
        Attendance.date <= last_day.date()
    ).all()
    
    # Create attendance lookup dictionary
    attendance_lookup = {att.date: att for att in month_attendance}
    
    # Generate calendar days with attendance status
    current_date = first_day
    while current_date <= last_day:
        day_data = {
            'date': current_date.day,
            'is_weekend': current_date.weekday() >= 5,
            'status': 'weekend' if current_date.weekday() >= 5 else None
        }
        
        if not day_data['is_weekend']:
            attendance = attendance_lookup.get(current_date.date())
            if attendance:
                # Calculate work duration if both time_in and time_out exist
                if attendance.time_in and attendance.time_out:
                    duration = datetime.datetime.combine(datetime.date.min, attendance.time_out) - \
                              datetime.datetime.combine(datetime.date.min, attendance.time_in)
                    hours_worked = duration.total_seconds() / 3600
                    
                    if hours_worked >= 8:
                        day_data['status'] = 'present'
                    elif hours_worked >= 4:
                        day_data['status'] = 'half-day'
                    else:
                        day_data['status'] = 'absent'
                else:
                    day_data['status'] = 'absent'
            else:
                if current_date.date() < today.date():
                    day_data['status'] = 'absent'
        
        calendar_days.append(day_data)
        current_date += datetime.timedelta(days=1)
    
    # Fetch only upcoming meetings for the dashboard
    now = dt.now(datetime.UTC)
    meetings = Meeting.query.filter_by(employee_id=current_user.id).filter(Meeting.date >= now).order_by(Meeting.date).limit(5).all()
    
    return render_template('profile.html', meetings=meetings, calendar_days=calendar_days, month_year=month_year)

@app.route("/attendance")
@login_required
def attendance():
    attendances = Attendance.query.filter_by(employee_id=current_user.id).all()
    return render_template('attendance.html', attendances=attendances)

@app.route("/meetings")
@login_required
def meetings():
    meetings = Meeting.query.filter_by(employee_id=current_user.id).all()
    return render_template('meetings.html', meetings=meetings)

# --- Message Routes ---

@app.route("/api/messages/<int:other_user_id>")
@login_required
def get_new_messages(other_user_id):
    after_id = request.args.get('after', type=int, default=0)
    
    messages = Message.query.filter(
        Message.id > after_id,
        ((Message.sender_id == current_user.id) & (Message.recipient_id == other_user_id) & (Message.deleted_by_sender == False)) |
        ((Message.sender_id == other_user_id) & (Message.recipient_id == current_user.id) & (Message.deleted_by_recipient == False))
    ).order_by(Message.timestamp.asc()).all()
    
    return jsonify({
        'messages': [{
            'id': msg.id,
            'content': msg.content,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'sender_id': msg.sender_id,
            'sender_name': msg.sender.name
        } for msg in messages]
    })

@app.route("/api/search_messages")
@login_required
def search_messages():
    query = request.args.get('q', '')
    if not query:
        return jsonify({'messages': []})
    
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.deleted_by_sender == False)) |
        ((Message.recipient_id == current_user.id) & (Message.deleted_by_recipient == False)),
        Message.content.ilike(f'%{query}%')
    ).order_by(Message.timestamp.desc()).limit(20).all()
    
    return jsonify({
        'messages': [{
            'id': msg.id,
            'content': msg.content,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'sender_name': msg.sender.name,
            'recipient_name': msg.recipient.name,
            'is_sent': msg.sender_id == current_user.id,
            'read': msg.read
        } for msg in messages]
    })

@app.route("/inbox")
@login_required
def inbox():
    # Get unread messages first, then read messages
    messages = Message.query.filter(
        Message.recipient_id == current_user.id,
        Message.deleted_by_recipient == False
    ).order_by(Message.read.asc(), Message.timestamp.desc()).all()
    
    # Mark all messages as read
    for message in messages:
        if not message.read:
            message.read = True
    db.session.commit()
    
    return render_template('inbox.html', messages=messages)

@app.route("/sent")
@login_required
def sent_messages():
    messages = Message.query.filter(
        Message.sender_id == current_user.id,
        Message.deleted_by_sender == False
    ).order_by(Message.timestamp.desc()).all()
    return render_template('sent.html', messages=messages)

@app.route("/chat/<int:other_user_id>")
@login_required
def chat(other_user_id):
    other_user = Employee.query.get_or_404(other_user_id)
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == other_user_id) & (Message.deleted_by_sender == False)) |
        ((Message.sender_id == other_user_id) & (Message.recipient_id == current_user.id) & (Message.deleted_by_recipient == False))
    ).order_by(Message.timestamp.asc()).all()
    
    # Mark messages as read
    for message in messages:
        if message.recipient_id == current_user.id and not message.read:
            message.read = True
    db.session.commit()
    
    form = MessageForm()
    return render_template('chat.html', messages=messages, other_user=other_user, form=form)

@app.route("/message/delete/<int:message_id>", methods=['POST'])
@login_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)
    if message.sender_id == current_user.id:
        message.deleted_by_sender = True
    elif message.recipient_id == current_user.id:
        message.deleted_by_recipient = True
    
    # If both sender and recipient have deleted the message, remove it from database
    if message.deleted_by_sender and message.deleted_by_recipient:
        db.session.delete(message)
    
    db.session.commit()
    flash('Message deleted.', 'success')
    return redirect(request.referrer or url_for('inbox'))

@app.route("/api/send_message/<int:recipient_id>", methods=['POST'])
@login_required
def api_send_message(recipient_id):
    content = request.form.get('content', '').strip()
    attachments = request.form.getlist('attachments[]')
    
    if not content and not attachments:
        return jsonify({'error': 'Message content or attachments are required'}), 400
    
    # Create the message
    new_message = Message(
        sender_id=current_user.id,
        recipient_id=recipient_id,
        content=content
    )
    db.session.add(new_message)
    db.session.flush()  # Get message ID before committing
    
    # Handle attachments
    message_attachments = []
    for filename in attachments:
        # Verify the file exists
        file_path = os.path.join(app.root_path, 'static', 'attachments', filename)
        if os.path.exists(file_path):
            attachment = MessageAttachment(
                message_id=new_message.id,
                filename=filename,
                file_type=mimetypes.guess_type(filename)[0],
                file_size=os.path.getsize(file_path)
            )
            message_attachments.append(attachment)
            db.session.add(attachment)
    
    db.session.commit()
    
    # Format attachments for response
    attachment_data = [{
        'filename': att.filename,
        'original_name': att.filename.split('_', 1)[1],  # Remove timestamp prefix
        'file_type': att.file_type,
        'file_size': att.file_size
    } for att in message_attachments]
    
    return jsonify({
        'id': new_message.id,
        'content': new_message.content,
        'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'sender_name': current_user.name,
        'attachments': attachment_data
    })

@app.route("/api/check_notifications")
@login_required
def check_notifications():
    # Get unread messages
    unread_messages = Message.query.filter(
        Message.recipient_id == current_user.id,
        Message.read == False,
        Message.deleted_by_recipient == False
    ).order_by(Message.timestamp.desc()).all()
    
    # Format messages for the response
    messages = [{
        'id': msg.id,
        'content': msg.content,
        'sender_name': msg.sender.name,
        'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    } for msg in unread_messages]
    
    return jsonify({
        'unread_count': len(unread_messages),
        'new_messages': messages
    })

@app.route("/api/messages/<int:message_id>/react", methods=['POST'])
@login_required
def react_to_message(message_id):
    emoji = request.form.get('emoji')
    if not emoji:
        return jsonify({'error': 'Emoji is required'}), 400
        
    message = Message.query.get_or_404(message_id)
    
    # Check if user already reacted with this emoji
    existing_reaction = MessageReaction.query.filter_by(
        message_id=message_id,
        user_id=current_user.id,
        emoji=emoji
    ).first()
    
    if existing_reaction:
        # Remove reaction if it already exists (toggle behavior)
        db.session.delete(existing_reaction)
        db.session.commit()
        return jsonify({'status': 'removed'})
    
    # Add new reaction
    reaction = MessageReaction(
        message_id=message_id,
        user_id=current_user.id,
        emoji=emoji
    )
    db.session.add(reaction)
    db.session.commit()
    
    return jsonify({
        'status': 'added',
        'reaction': {
            'id': reaction.id,
            'emoji': emoji,
            'user_name': current_user.name
        }
    })

@app.route("/api/message_statuses")
@login_required
def check_message_statuses():
    since = request.args.get('since')
    if not since:
        return jsonify({'error': 'Missing since parameter'}), 400
    
    try:
        since_dt = datetime.datetime.fromisoformat(since.replace('Z', '+00:00'))
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400
    
    # Get status updates for sent messages
    messages = Message.query.filter(
        Message.sender_id == current_user.id,
        Message.timestamp >= since_dt
    ).all()
    
    updates = [{
        'message_id': msg.id,
        'delivered': True,  # Message exists in DB so it's delivered
        'read': msg.read,
        'timestamp': msg.timestamp.isoformat()
    } for msg in messages]
    
    return jsonify({'updates': updates})

@app.route("/api/messages/upload", methods=['POST'])
@login_required
def upload_message_attachment():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Validate file type
    file_ext = validate_file_mime_type(file)
    if not file_ext:
        return jsonify({'error': 'Invalid file type'}), 400
    
    # Create attachments directory if it doesn't exist
    attachments_dir = os.path.join(app.root_path, 'static', 'attachments')
    os.makedirs(attachments_dir, exist_ok=True)
    
    # Save file with unique name and correct extension
    filename = secure_filename(f"{int(time.time())}_{file.filename}")
    base_name = os.path.splitext(filename)[0]
    safe_filename = f"{base_name}{file_ext}"
    file_path = os.path.join(attachments_dir, safe_filename)
    file.save(file_path)
    
    # Get file size and type
    file_size = os.path.getsize(file_path)
    file_type = file.content_type
    
    return jsonify({
        'filename': safe_filename,
        'original_name': file.filename,
        'file_type': file_type,
        'file_size': file_size
    })

# --- Admin Routes ---


@app.route("/admin")
@login_required
def admin():
    if not is_admin():
        flash("You are not authorized to access this page.", "danger")
        return redirect(url_for("profile"))
    employees = Employee.query.all()
    return render_template('admin.html', employees=employees)

@app.route("/admin/employee/<int:employee_id>")
@login_required
def view_employee_profile(employee_id):
    if not is_admin():
        flash("You are not authorized to view employee profiles.", "danger")
        return redirect(url_for("profile"))

    employee = Employee.query.get_or_404(employee_id)
    now = dt.now(datetime.UTC)
    meetings = Meeting.query.filter_by(employee_id=employee.id).filter(Meeting.date >= now).order_by(Meeting.date).limit(5).all()
    return render_template('profile.html', employee=employee, meetings=meetings)  # Reuse the profile template


@app.route("/admin/employee/new", methods=['GET', 'POST'])
@login_required
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
@login_required
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
@login_required
def view_employee_attendance(employee_id):
    if not is_admin():
        flash("You are not authorized to view attendance.", "danger")
        return redirect(url_for("profile"))

    employee = Employee.query.get_or_404(employee_id)
    attendances = Attendance.query.filter_by(employee_id=employee.id).all()
    return render_template('employee_attendance.html', employee=employee, attendances=attendances)

@app.route("/create_meeting", methods=['GET', 'POST'])
@login_required
def create_meeting():
    if not is_admin():
        flash("You are not authorized to create meetings.", "danger")
        return redirect(url_for("profile"))

    form = MeetingForm()
    if form.validate_on_submit():
        combined_datetime = datetime.combine(form.date.data, form.time.data)
        new_meeting = Meeting(
            employee_id=current_user.id,
            title=form.title.data,
            date=combined_datetime,
            location=form.location.data,
            description=form.description.data
        )
        db.session.add(new_meeting)
        db.session.commit()
        flash('Meeting created successfully!', 'success')
        return redirect(url_for('admin'))

    return render_template('create_meeting.html', form=form)


@app.route("/calendar")
@login_required
def calendar():
    if is_admin():
        # Admins can see all meetings
        meetings = Meeting.query.all()
    else:
        # Regular employees only see their own meetings
        meetings = Meeting.query.filter_by(employee_id=current_user.id).all()
    return render_template("calendar.html", meetings=meetings)

@app.route("/update_profile_picture", methods=['POST'])
@login_required
def update_profile_picture():
    if 'profile_picture' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('profile'))
    
    file = request.files['profile_picture']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('profile'))
    
    if file and allowed_file(file.filename):
        # Delete old profile picture if it exists and isn't default
        if current_user.profile_picture != 'default.jpg':
            old_file = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], current_user.profile_picture)
            if os.path.exists(old_file):
                os.remove(old_file)

        # Save new profile picture
        filename = secure_filename(f"{current_user.employee_id}_{file.filename}")
        file.save(os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename))
        
        # Update database
        current_user.profile_picture = filename
        db.session.commit()
        
        flash('Profile picture updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    flash('Invalid file type. Please use PNG, JPG, JPEG or GIF', 'danger')
    return redirect(url_for('profile'))

# --- WebView Integration ---


def start_server():
    app.run(debug=True, host='0.0.0.0', port=5000)  # Be explicit about host and port

if __name__ == '__main__':
    # --- Database setup ---
    with app.app_context():
        db.drop_all()  # Reset database during development
        db.create_all()
        # Create admin user if it doesn't exist
        admin_user = Employee.query.filter_by(employee_id='admin').first()
        if not admin_user:
            admin_user = Employee(
                employee_id='admin',
                name='Harsh Raj Jaiswal',
                email='admin@example.com',
                role='admin',
                mobile_number='7754938396'
            )
            admin_user.set_password('password')
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