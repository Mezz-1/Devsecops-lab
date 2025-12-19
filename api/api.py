from flask import Flask, request
import sqlite3
import subprocess
import hashlib
import os
import re

app = Flask(__name__)
# In production, use environment variable
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-12345')

def sanitize_hostname(host):
    """Sanitize hostname input to prevent command injection"""
    # Allow only alphanumeric, dots, and hyphens (for domain names/IPs)
    if re.match(r'^[a-zA-Z0-9\.\-]+$', host):
        return host
    raise ValueError("Invalid hostname format")

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Use parameterized query to prevent SQL injection
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))

    result = cursor.fetchone()
    if result:
        return {'status': 'success', 'user': username}
    return {'status': 'error', 'message': 'Invalid credentials'}

@app.route('/ping', methods=['POST'])
def ping():
    host = request.json.get('host', '')
    
    # Validate and sanitize input
    try:
        sanitized_host = sanitize_hostname(host)
    except ValueError:
        return {'error': 'Invalid hostname'}, 400
    
    # Use shell=False and pass command as list to prevent injection
    cmd = ['ping', '-c', '1', sanitized_host]
    
    try:
        output = subprocess.check_output(cmd, shell=False, stderr=subprocess.STDOUT, timeout=5)
        return {'output': output.decode()}
    except subprocess.CalledProcessError as e:
        return {'error': f'Ping failed: {e.output.decode()}'}, 400
    except subprocess.TimeoutExpired:
        return {'error': 'Ping timeout'}, 408

@app.route('/compute', methods=['POST'])
def compute():
    expression = request.json.get('expression', '1+1')
  
    import ast
    try:
        node = ast.parse(expression, mode='eval')
        allowed_names = {'__builtins__': None}
        
        class SafeEval(ast.NodeVisitor):
            def visit(self, node):
                if not isinstance(node, self.ALLOWED_NODE_TYPES):
                    raise ValueError(f"Unsafe expression: {type(node).__name__}")
                return super().visit(node)
            
            ALLOWED_NODE_TYPES = (ast.Expression, ast.Constant, ast.BinOp, 
                                  ast.UnaryOp, ast.Add, ast.Sub, ast.Mult, 
                                  ast.Div, ast.Pow, ast.USub, ast.UAdd)
        
        SafeEval().visit(node)
        result = eval(expression, allowed_names)
        return {'result': result}
    except (SyntaxError, ValueError) as e:
        return {'error': 'Invalid or unsafe expression'}, 400

@app.route('/hash', methods=['POST'])
def hash_password():
    pwd = request.json.get('password', 'admin')

    hashed = hashlib.sha256(pwd.encode()).hexdigest()
    
 
    
    return {'hash': hashed, 'algorithm': 'SHA-256'}

@app.route('/readfile', methods=['POST'])
def readfile():
    filename = request.json.get('filename', 'test.txt')
    
    # Prevent directory traversal attacks
    base_dir = os.path.abspath('files/')  # Restrict to specific directory
    filepath = os.path.abspath(os.path.join(base_dir, filename))
    
    # Ensure the file is within the allowed directory
    if not filepath.startswith(base_dir):
        return {'error': 'Access denied'}, 403
    
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return {'content': content}
    except FileNotFoundError:
        return {'error': 'File not found'}, 404
    except IOError:
        return {'error': 'Unable to read file'}, 500

@app.route('/debug', methods=['GET'])
def debug():
    # Never expose secrets in debug endpoints
    # In production, disable or protect this endpoint
    debug_info = {
        'debug': True,
        'environment_keys': list(os.environ.keys()),  # Don't show values
        'python_version': os.sys.version
    }
    return debug_info

@app.route('/hello', methods=['GET'])
def hello():
    return {'message': 'Welcome to the DevSecOps vulnerable API'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)  # debug=False in production