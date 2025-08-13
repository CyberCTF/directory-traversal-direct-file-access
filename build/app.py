from flask import Flask, render_template, request, send_file, abort
import os
import urllib.parse

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Create uploads folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Create some test files
def create_sample_files():
    sample_files = [
        ('document.txt', 'This is a confidential document.'),
        ('report.pdf', 'Monthly report - Sensitive data.'),
        ('image.png', 'Test image.'),
        ('config.txt', 'System configuration.'),
        ('flag.txt', 'FLAG{direct_file_access_successful}')
    ]
    
    for filename, content in sample_files:
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(filepath):
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)

create_sample_files()

def is_safe_path(file_path):
    """Security function - allows only direct access to /etc/passwd"""
    # Allow only direct access to /etc/passwd
    if file_path == '/etc/passwd':
        return True
    # Block all path traversal
    if '../' in file_path or '..\\' in file_path:
        return False
    return True

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/files')
def files():
    """File listing page"""
    files_list = []
    try:
        for filename in os.listdir(UPLOAD_FOLDER):
            if os.path.isfile(os.path.join(UPLOAD_FOLDER, filename)):
                files_list.append({
                    'name': filename,
                    'size': os.path.getsize(os.path.join(UPLOAD_FOLDER, filename))
                })
    except Exception as e:
        files_list = []
    
    return render_template('files.html', files=files_list)

@app.route('/view')
def view_file():
    """Vulnerable endpoint for path traversal"""
    filename = request.args.get('file', '')
    
    if not filename:
        abort(400, description="Filename required")
    
    # URL decoding
    decoded_filename = urllib.parse.unquote(filename)
    
    # Security check
    if not is_safe_path(decoded_filename):
        abort(404, description="Error 404")
    
    # If it's /etc/passwd, direct access
    if decoded_filename == '/etc/passwd':
        try:
            with open('/etc/passwd', 'r', encoding='utf-8') as f:
                content = f.read()
            return render_template('view.html', filename=filename, content=content)
        except Exception as e:
            abort(500, description=f"Error reading file: {str(e)}")
    
    # Build path for other files
    file_path = os.path.join(UPLOAD_FOLDER, decoded_filename)
    file_path = os.path.normpath(file_path)
    
    # Check if file exists
    if not os.path.exists(file_path):
        abort(404, description="Error 404")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return render_template('view.html', filename=filename, content=content)
    except Exception as e:
        abort(500, description=f"Error reading file: {str(e)}")

@app.route('/download')
def download_file():
    """Vulnerable download endpoint"""
    filename = request.args.get('file', '')
    
    if not filename:
        abort(400, description="Filename required")
    
    # URL decoding
    decoded_filename = urllib.parse.unquote(filename)
    
    # Security check
    if not is_safe_path(decoded_filename):
        abort(404, description="Error 404")
    
    # If it's /etc/passwd, direct access
    if decoded_filename == '/etc/passwd':
        try:
            return send_file('/etc/passwd', as_attachment=True)
        except Exception as e:
            abort(500, description=f"Error downloading file: {str(e)}")
    
    # Build path for other files
    file_path = os.path.join(UPLOAD_FOLDER, decoded_filename)
    file_path = os.path.normpath(file_path)
    
    if not os.path.exists(file_path):
        abort(404, description="Error 404")
    
    try:
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        abort(500, description=f"Error downloading file: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
