from flask import Flask, request, jsonify
import subprocess
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/upload', methods=['POST'])
def upload_and_mutate():
    uploaded_file = request.files.get('file')
    if not uploaded_file:
        return 'No file uploaded', 400

    filename = uploaded_file.filename
    if not filename.endswith('.txt'):
        return 'Only .txt files are allowed.', 400

    filepath = os.path.join(UPLOAD_FOLDER, filename)
    uploaded_file.save(filepath)
    
    module_name = filename[:-3]  # Remove '.py'

    test_code = f'''
import unittest
import {module_name}

class TestUploadedModule(unittest.TestCase):
    def test_dummy(self):
        assert True

if __name__ == '__main__':
    unittest.main()
'''
    test_filepath = os.path.join(UPLOAD_FOLDER, f'test_{filename}')
    with open(test_filepath, 'w') as f:
        f.write(test_code)

    try:
        command = [
    'python', '-m', 'mutpy',
    '--target', filepath,
    '--unit-test', test_filepath,
    '--runner', 'unittest'
]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        result = stdout.decode('utf-8') + '\n' + stderr.decode('utf-8')
    except Exception as e:
        return f'Error running MutPy: {str(e)}', 500

    return result

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
