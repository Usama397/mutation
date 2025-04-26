from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from functools import wraps
import re
import subprocess

# Initialize Flask app
app = Flask(__name__)

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'  # Required for session management

# Configure file upload settings
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'py'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize the database
db = SQLAlchemy(app)

# Debugging: Print the database URI
print("Database URI:", app.config['SQLALCHEMY_DATABASE_URI'])

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # Increased length for hashed passwords

    def __repr__(self):
        return f'<User {self.username}>'

# Create the database tables (run this once)
with app.app_context():
    print("Creating database tables...")
    db.create_all()  # Create tables if they don't exist
    print("Database tables created.")

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Login Required Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_user():
    return dict(logged_in='user_id' in session, username=session.get('username'))
@app.route('/user')
@login_required
def user_profile():
    user = User.query.get(session['user_id'])
    return render_template('user.html', user=user)

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# About route
@app.route('/about')
def about():
    return render_template('about.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username']
        password = request.form['password']

        # Check if the user exists in the database
        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()

        if user and check_password_hash(user.password, password):
            # Log the user in by storing their ID and username in the session
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username/email or password.', 'error')

    return render_template('login.html')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))

        # Check if the username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists.', 'error')
            return redirect(url_for('signup'))

        # Hash the password before storing it
        hashed_password = generate_password_hash(password)

        # Create a new user
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

# Upload route (Protected)
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'targetFile' not in request.files or 'testFile' not in request.files:
            return 'Both Target and Test files are required!', 400

        target_file = request.files['targetFile']
        test_file = request.files['testFile']

        if target_file.filename == '' or test_file.filename == '':
            return 'No selected files!', 400

        if allowed_file(target_file.filename) and allowed_file(test_file.filename):
            # Secure filenames
            target_filename = secure_filename(target_file.filename)
            test_filename = secure_filename(test_file.filename)

            # Save files
            target_filepath = os.path.join(app.config['UPLOAD_FOLDER'], target_filename)
            test_filepath = os.path.join(app.config['UPLOAD_FOLDER'], test_filename)

            target_file.save(target_filepath)
            test_file.save(test_filepath)

            # ✅ Make uploads/ a package (if not already)
            init_file = os.path.join(app.config['UPLOAD_FOLDER'], '__init__.py')
            if not os.path.exists(init_file):
                open(init_file, 'a').close()

            try:
                # ✅ Build correct Python module paths
                relative_target_path = os.path.relpath(target_filepath, start=app.root_path)
                relative_test_path = os.path.relpath(test_filepath, start=app.root_path)

                target_module = relative_target_path.replace('/', '.').replace('\\', '.').replace('.py', '')
                test_module = relative_test_path.replace('/', '.').replace('\\', '.').replace('.py', '')

                # ✅ Now use mut.py directly (like Colab)
                command = [
                    'python3', '-m', 'mutpy',
                    '--target', target_module,
                    '--unit-test', test_module,
                    '--runner', 'unittest'
                ]


                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()

                result = stdout.decode('utf-8') + '\n' + stderr.decode('utf-8')

                return result  # ✅ Directly returning mutation result

            except Exception as e:
                return f'Error running mutation testing: {str(e)}', 500

        else:
            return 'Invalid file types, only .py files are allowed.', 400

    return render_template('upload.html')




# Report route (Protected)
@app.route('/report')
@login_required
def report():
    mutation_result = session.get('mutation_result', '')

    # Extract summary values from the text
    total_mutants = 0
    killed_mutants = 0
    survived_mutants = 0
    mutation_score = 0.0
    mutants_details = []

    if mutation_result:
        # Parse final summary
        match_total = re.search(r'- all: (\d+)', mutation_result)
        match_killed = re.search(r'- killed: (\d+)', mutation_result)
        match_survived = re.search(r'- survived: (\d+)', mutation_result)
        match_score = re.search(r'Mutation score.*?: ([\d\.]+)%', mutation_result)

        if match_total:
            total_mutants = int(match_total.group(1))
        if match_killed:
            killed_mutants = int(match_killed.group(1))
        if match_survived:
            survived_mutants = int(match_survived.group(1))
        if match_score:
            mutation_score = float(match_score.group(1))

        # Parse detailed mutants
        mutant_lines = re.findall(r'\[#\s*(\d+)\] (.*?) \[(.*?)\] (.*?) by (.*?) ', mutation_result)
        for line in mutant_lines:
            mutants_details.append({
                'test_id': line[0],
                'mutation_type': line[1],
                'execution_time': line[2],
                'status': 'Killed' if 'killed' in line[3] else 'Survived',
            })

    return render_template('report.html',
        total_mutants=total_mutants,
        killed_mutants=killed_mutants,
        survived_mutants=survived_mutants,
        mutation_score=mutation_score,
        mutants_details=mutants_details
    )


# Logout route
@app.route('/logout')
def logout():
    # Clear the session to log the user out
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# Team route
@app.route('/team')
def team():
    return render_template('team.html')

# Privacy route
@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

# Admin login route
@app.route('/adminlogin')
def adminlogin():
    return render_template('adminlogin.html')

# User management route
@app.route('/user')
def user():
    return render_template('user.html')

# Admin panel route
@app.route('/admin')
def admin():
    return render_template('adminpanel.html')

# Manage reports route
@app.route('/managereport')
def managereports():
    return render_template('managereports.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)