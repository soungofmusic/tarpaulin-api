from functools import wraps
import json
import os
from flask import Flask, request, make_response
from google.cloud import datastore, storage
from jose import jwt
from urllib.request import urlopen
import requests
from dotenv import load_dotenv

# Initialize app and load config
load_dotenv()
app = Flask(__name__)

# Cloud services setup
datastore_client = datastore.Client()
storage_client = storage.Client()
BUCKET_NAME = os.environ.get('BUCKET_NAME')

# Auth0 configuration
AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN')
ALGORITHMS = ['RS256']
API_AUDIENCE = os.environ.get('API_AUDIENCE')
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')

class AuthError(Exception):
    """Custom exception for authentication errors"""
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

def get_token_auth_header():
    """Extract and validate JWT from Authorization header"""
    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError("Unauthorized", 401)

    parts = auth.split()
    if parts[0].lower() != 'bearer' or len(parts) != 2:
        raise AuthError("Unauthorized", 401)

    return parts[1]

def requires_auth(f):
    """Decorator to protect routes with JWT auth"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = get_token_auth_header()
            jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
            jwks = json.loads(jsonurl.read())
            unverified_header = jwt.get_unverified_header(token)
            
            if 'kid' not in unverified_header:
                raise AuthError("Unauthorized", 401)

            # Find matching key
            rsa_key = {}
            for key in jwks['keys']:
                if key['kid'] == unverified_header['kid']:
                    rsa_key = {
                        'kty': key['kty'],
                        'kid': key['kid'],
                        'use': key['use'],
                        'n': key['n'],
                        'e': key['e']
                    }
            
            if rsa_key:
                try:
                    payload = jwt.decode(
                        token,
                        rsa_key,
                        algorithms=ALGORITHMS,
                        audience=API_AUDIENCE,
                        issuer=f'https://{AUTH0_DOMAIN}/'
                    )
                    request.user = payload
                    return f(*args, **kwargs)
                except (jwt.ExpiredSignatureError, jwt.JWTClaimsError):
                    raise AuthError("Unauthorized", 401)
            raise AuthError("Unauthorized", 401)
            
        except AuthError as e:
            return {"Error": e.error}, e.status_code
        except Exception:
            return {"Error": "Unauthorized"}, 401
            
    return decorated

class UserModel:
    """Handles user-related database operations"""
    
    def __init__(self):
        self.client = datastore_client
        self.kind = 'users'

    def get_user_by_sub(self, sub):
        """Get user by Auth0 subject ID"""
        query = self.client.query(kind=self.kind)
        query.add_filter('sub', '=', sub)
        result = list(query.fetch(1))
        if result:
            user = result[0]
            user['id'] = user.key.id
            return user
        return None

    def get_user_by_id(self, user_id):
        """Get user by internal ID"""
        try:
            key = self.client.key(self.kind, int(user_id))
            user = self.client.get(key)
            if user:
                user['id'] = user.key.id
                return user
            return None
        except Exception:
            return None

    def get_all_users(self):
        """Get basic info for all users"""
        query = self.client.query(kind=self.kind)
        users = list(query.fetch())
        return [{
            'id': user.key.id,
            'role': user['role'],
            'sub': user['sub']
        } for user in users]

    def format_user_response(self, user, base_url):
        """Format user data for API response"""
        response = {
            'id': user['id'],
            'role': user['role'],
            'sub': user['sub']
        }
        
        if user.get('avatar_exists', False):
            response['avatar_url'] = f"{base_url}/users/{user['id']}/avatar"
            
        if user['role'] in ['instructor', 'student']:
            courses = user.get('courses', [])
            response['courses'] = [f"{base_url}/courses/{course_id}" for course_id in courses]
            
        return response

    def update_user_avatar(self, user_id, avatar_exists):
        """Update user's avatar status"""
        try:
            key = self.client.key(self.kind, int(user_id))
            user = self.client.get(key)
            if user:
                user['avatar_exists'] = avatar_exists
                self.client.put(user)
                return True
            return False
        except Exception as e:
            print(f"Error updating avatar status: {e}")
            return False

    def add_course_to_user(self, user_id, course_id):
        """Add course to user's course list"""
        user = self.get_user_by_id(user_id)
        if user:
            courses = user.get('courses', [])
            if str(course_id) not in courses:
                courses.append(str(course_id))
                user['courses'] = courses
                self.client.put(user)

    def remove_course_from_user(self, user_id, course_id):
        """Remove course from user's course list"""
        user = self.get_user_by_id(user_id)
        if user and 'courses' in user:
            if course_id in user['courses']:
                user['courses'].remove(course_id)
                self.client.put(user)

class CourseModel:
    """Handles course-related database operations"""
    
    def __init__(self):
        self.client = datastore_client
        self.kind = 'courses'

    def create_course(self, data):
        """Create new course"""
        entity = datastore.Entity(self.client.key(self.kind))
        entity.update({
            'subject': data['subject'],
            'number': data['number'],
            'title': data['title'],
            'term': data['term'],
            'instructor_id': data['instructor_id'],
            'students': []
        })
        self.client.put(entity)
        entity['id'] = entity.key.id
        return entity

    def get_course_by_id(self, course_id):
        """Get course by ID"""
        try:
            key = self.client.key(self.kind, int(course_id))
            course = self.client.get(key)
            if course:
                course['id'] = course.key.id
                return course
            return None
        except:
            return None

    def list_courses(self, offset=0, limit=3, subject=None, number=None, term=None, sort_by='subject', sort_order='asc'):
        """Get courses with filtering and pagination"""
        query = self.client.query(kind=self.kind)

        # Apply filters
        if subject:
            query.add_filter('subject', '=', subject)
        if number:
            query.add_filter('number', '=', number)
        if term:
            query.add_filter('term', '=', term)

        # Sort results
        query.order = [f'-{sort_by}'] if sort_order == 'desc' else [sort_by]

        courses = list(query.fetch(limit=limit+1, offset=offset))
        has_more = len(courses) > limit
        courses = courses[:limit]

        for course in courses:
            course['id'] = course.key.id

        return courses, has_more

    def format_course_response(self, course, base_url):
        """Format course data for API response"""
        return {
            'id': course['id'],
            'subject': course['subject'],
            'number': course['number'],
            'title': course['title'],
            'term': course['term'],
            'instructor_id': course['instructor_id'],
            'self': f"{base_url}/courses/{course['id']}"
        }

    def update_course(self, course_id, data):
        """Update course details"""
        course = self.get_course_by_id(course_id)
        if course:
            for key, value in data.items():
                if key != 'students':
                    course[key] = value
            self.client.put(course)
            return course
        return None

    def delete_course(self, course_id):
        """Delete course and update related records"""
        key = self.client.key(self.kind, int(course_id))
        course = self.client.get(key)
        if course:
            instructor_id = course['instructor_id']
            user_model.remove_course_from_user(instructor_id, course_id)
            
            for student_id in course.get('students', []):
                user_model.remove_course_from_user(student_id, course_id)
                
            self.client.delete(key)
            return True
        return False

    def update_enrollment(self, course_id, add_students, remove_students):
        """Update student enrollment"""
        course = self.get_course_by_id(course_id)
        if not course:
            return False
            
        students = set(course.get('students', []))
        
        for student_id in remove_students:
            if student_id in students:
                students.remove(student_id)
                user_model.remove_course_from_user(student_id, course_id)
                
        for student_id in add_students:
            if student_id not in students:
                students.add(student_id)
                user_model.add_course_to_user(student_id, course_id)
                
        course['students'] = list(students)
        self.client.put(course)
        return True

# Initialize models
user_model = UserModel()
course_model = CourseModel()

# === Routes ===

# Authentication routes
@app.route('/users/login', methods=['POST'])
def user_login():
    """Handle login and token generation"""
    if not request.is_json:
        return {"Error": "The request body is invalid"}, 400
        
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return {"Error": "The request body is invalid"}, 400

    payload = {
        'grant_type': 'password',
        'username': data['username'],
        'password': data['password'],
        'audience': API_AUDIENCE,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }

    response = requests.post(f'https://{AUTH0_DOMAIN}/oauth/token', json=payload)
    
    if response.status_code == 200:
        token = response.json().get('access_token')
        return {'token': token}, 200
    return {"Error": "Unauthorized"}, 401

# User routes
@app.route('/users', methods=['GET'])
@requires_auth
def get_users():
    """Get all users (admin only)"""
    try:
        requester = user_model.get_user_by_sub(request.user['sub'])
        if not requester:
            return {"Error": "Unauthorized"}, 401
        
        if requester['role'] != 'admin':
            return {"Error": "You don't have permission on this resource"}, 403
        
        users = user_model.get_all_users()
        return users, 200
        
    except Exception as e:
        print(e)
        return {"Error": "Not found"}, 404

@app.route('/users/<int:user_id>', methods=['GET'])
@requires_auth
def get_user(user_id):
    """Get user details"""
    requester = user_model.get_user_by_sub(request.user['sub'])
    if not requester:
        return {"Error": "Unauthorized"}, 401
        
    user = user_model.get_user_by_id(user_id)
    if not user:
        return {"Error": "Not found"}, 404

    if requester['role'] != 'admin' and requester['id'] != user['id']:
        return {"Error": "You don't have permission on this resource"}, 403

    response = user_model.format_user_response(user, request.url_root.rstrip('/'))
    return response, 200

# Avatar routes
@app.route('/users/<int:user_id>/avatar', methods=['POST'])
@requires_auth
def upload_avatar(user_id):
    """Upload user avatar"""
    requester = user_model.get_user_by_sub(request.user['sub'])
    if not requester:
        return {"Error": "Unauthorized"}, 401
    
    if str(requester['id']) != str(user_id):
        return {"Error": "You don't have permission on this resource"}, 403

    if 'file' not in request.files:
        return {"Error": "The request body is invalid"}, 400

    file = request.files['file']
    if not file:
        return {"Error": "The request body is invalid"}, 400

    try:
        file_data = file.read()
        if not file_data:
            return {"Error": "The request body is invalid"}, 400

        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(f'avatars/{user_id}.png')
        blob.upload_from_string(file_data, content_type='image/png')

        if not user_model.update_user_avatar(user_id, True):
            blob.delete()
            return {"Error": "Not found"}, 404

        return {
            "avatar_url": f"{request.url_root.rstrip('/')}/users/{user_id}/avatar"
        }, 200

    except Exception as e:
        print(f"Upload error: {str(e)}")
        return {"Error": "The request body is invalid"}, 400

@app.route('/users/<int:user_id>/avatar', methods=['GET'])
@requires_auth
def get_avatar(user_id):
    """Get user avatar"""
    requester = user_model.get_user_by_sub(request.user['sub'])
    if not requester:
        return {"Error": "Unauthorized"}, 401
        
    if str(requester['id']) != str(user_id):
        return {"Error": "You don't have permission on this resource"}, 403

    user = user_model.get_user_by_id(user_id)
    if not user or not user.get('avatar_exists', False):
        return {"Error": "Not found"}, 404

    try:
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(f'avatars/{user_id}.png')
        
        if not blob.exists():
            user_model.update_user_avatar(user_id, False)
            return {"Error": "Not found"}, 404

        image_data = blob.download_as_bytes()
        response = make_response(image_data)
        response.headers.set('Content-Type', 'image/png')
        return response

    except Exception as e:
        print(f"Avatar download error: {str(e)}")
        return {"Error": "Not found"}, 404

@app.route('/users/<int:user_id>/avatar', methods=['DELETE'])
@requires_auth
def delete_avatar(user_id):
    """Delete user avatar"""
    requester = user_model.get_user_by_sub(request.user['sub'])
    if not requester:
        return {"Error": "Unauthorized"}, 401
    
    if str(requester['id']) != str(user_id):
        return {"Error": "You don't have permission on this resource"}, 403

    user = user_model.get_user_by_id(user_id)
    if not user or not user.get('avatar_exists', False):
        return {"Error": "Not found"}, 404

    try:
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(f'avatars/{user_id}.png')
        
        if blob.exists():
            blob.delete()

        if not user_model.update_user_avatar(user_id, False):
            return {"Error": "User not found"}, 404
        
        return '', 204

    except Exception as e:
        print(f"Avatar delete error: {str(e)}")
        return {"Error": "Not found"}, 404

# Course routes
@app.route('/courses', methods=['POST'])
@requires_auth
def create_course():
    """Create new course (admin only)"""
    requester = user_model.get_user_by_sub(request.user['sub'])
    if not requester:
        return {"Error": "Unauthorized"}, 401
        
    if requester['role'] != 'admin':
        return {"Error": "You don't have permission on this resource"}, 403

    if not request.is_json:
        return {"Error": "The request body is invalid"}, 400
        
    data = request.get_json()
    required_fields = ['subject', 'number', 'title', 'term', 'instructor_id']
    if not data or not all(field in data for field in required_fields):
        return {"Error": "The request body is invalid"}, 400

    instructor = user_model.get_user_by_id(data['instructor_id'])
    if not instructor or instructor['role'] != 'instructor':
        return {"Error": "The request body is invalid"}, 400

    course = course_model.create_course(data)
    user_model.add_course_to_user(data['instructor_id'], course.id)
    
    response = course_model.format_course_response(course, request.url_root.rstrip('/'))
    return response, 201

@app.route('/courses', methods=['GET'])
def get_courses():
    """List courses with optional filtering and pagination"""
    offset = int(request.args.get('offset', '0'))
    limit = int(request.args.get('limit', '3'))
    
    filters = {
        'subject': request.args.get('subject'),
        'number': request.args.get('number'),
        'term': request.args.get('term'),
        'sort_by': request.args.get('sort_by', 'subject'),
        'sort_order': request.args.get('sort_order', 'asc')
    }

    courses, has_more = course_model.list_courses(offset=offset, limit=limit, **filters)

    response = {
        'courses': [course_model.format_course_response(c, request.url_root.rstrip('/')) 
                   for c in courses]
    }

    if has_more:
        next_offset = offset + limit
        response['next'] = f"{request.url_root.rstrip('/')}/courses?limit={limit}&offset={next_offset}"

    return response, 200

@app.route('/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):
    """Get course details"""
    course = course_model.get_course_by_id(course_id)
    if not course:
        return {"Error": "Not found"}, 404
        
    response = course_model.format_course_response(course, request.url_root.rstrip('/'))
    return response, 200

@app.route('/courses/<int:course_id>', methods=['PATCH'])
@requires_auth
def update_course(course_id):
    """Update course details (admin only)"""
    requester = user_model.get_user_by_sub(request.user['sub'])
    if not requester:
        return {"Error": "Unauthorized"}, 401

    if requester['role'] != 'admin':
        return {"Error": "You don't have permission on this resource"}, 403

    course = course_model.get_course_by_id(course_id)
    if not course:
        return {"Error": "You don't have permission on this resource"}, 403

    if not request.is_json:
        return {"Error": "The request body is invalid"}, 400

    data = request.get_json()
    if 'instructor_id' in data:
        instructor = user_model.get_user_by_id(data['instructor_id'])
        if not instructor or instructor['role'] != 'instructor':
            return {"Error": "The request body is invalid"}, 400
            
        user_model.remove_course_from_user(course['instructor_id'], course_id)
        user_model.add_course_to_user(data['instructor_id'], course_id)

    updated_course = course_model.update_course(course_id, data)
    response = course_model.format_course_response(updated_course, request.url_root.rstrip('/'))
    return response, 200

@app.route('/courses/<int:course_id>', methods=['DELETE'])
@requires_auth
def delete_course(course_id):
    """Delete course (admin only)"""
    requester = user_model.get_user_by_sub(request.user['sub'])
    if not requester:
        return {"Error": "Unauthorized"}, 401

    if requester['role'] != 'admin':
        return {"Error": "You don't have permission on this resource"}, 403

    course = course_model.get_course_by_id(course_id)
    if not course:
        return {"Error": "You don't have permission on this resource"}, 403

    course_model.delete_course(course_id)
    return '', 204

@app.route('/courses/<int:course_id>/students', methods=['PATCH'])
@requires_auth
def update_enrollment(course_id):
    """Update course enrollment"""
    requester = user_model.get_user_by_sub(request.user['sub'])
    if not requester:
        return {"Error": "Unauthorized"}, 401

    course = course_model.get_course_by_id(course_id)
    if not course:
        return {"Error": "You don't have permission on this resource"}, 403

    if requester['role'] != 'admin' and str(requester['id']) != str(course['instructor_id']):
        return {"Error": "You don't have permission on this resource"}, 403

    if not request.is_json:
        return {"Error": "The request body is invalid"}, 400

    data = request.get_json()
    if 'add' not in data or 'remove' not in data:
        return {"Error": "The request body is invalid"}, 400

    add_ids = data.get('add', [])
    remove_ids = data.get('remove', [])

    # Validate enrollment data
    if set(add_ids) & set(remove_ids):
        return {"Error": "Enrollment data is invalid"}, 409

    for student_id in add_ids + remove_ids:
        student = user_model.get_user_by_id(student_id)
        if not student or student['role'] != 'student':
            return {"Error": "Enrollment data is invalid"}, 409

    course_model.update_enrollment(course_id, add_ids, remove_ids)
    return '', 200

@app.route('/courses/<int:course_id>/students', methods=['GET'])
@requires_auth
def get_enrollment(course_id):
    """Get course enrollment"""
    requester = user_model.get_user_by_sub(request.user['sub'])
    if not requester:
        return {"Error": "Unauthorized"}, 401

    course = course_model.get_course_by_id(course_id)
    if not course:
        return {"Error": "You don't have permission on this resource"}, 403

    if requester['role'] != 'admin' and str(requester['id']) != str(course['instructor_id']):
        return {"Error": "You don't have permission on this resource"}, 403

    return course.get('students', []), 200

# Error handlers
@app.errorhandler(AuthError)
def handle_auth_error(ex):
    """Handle authentication errors"""
    return {"Error": ex.error}, ex.status_code

@app.errorhandler(400)
def bad_request(error):
    """Handle bad request errors"""
    return {"Error": "The request body is invalid"}, 400

@app.errorhandler(404)
def not_found(error):
    """Handle not found errors"""
    return {"Error": "Not found"}, 404

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)