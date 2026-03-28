import os
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client
from dotenv import load_dotenv
import jwt
import stripe

load_dotenv()

app = Flask(__name__)
CORS(app)

supabase: Client = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_KEY")
)

SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
stripe.api_key = os.getenv("STRIPE_API_KEY")


# ---------- AUTH MIDDLEWARE ----------

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Missing or invalid authorization header"}), 401
        token = auth_header.split(" ")[1]
        try:
            decoded = jwt.decode(
                token,
                SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                audience="authenticated"
            )
            request.user = decoded
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({"error": "Invalid token", "details": str(e)}), 401
        return f(*args, **kwargs)
    return decorated


# ---------- JOBS ----------

@app.route('/api/jobs', methods=['GET'])
def list_jobs():
    limit = request.args.get('limit', 20, type=int)
    offset = request.args.get('offset', 0, type=int)
    category = request.args.get('category')

    query = supabase.table('jobs') \
        .select('*, profiles!jobs_user_id_fkey(first_name, last_name)') \
        .eq('status', 'open') \
        .order('created_at', desc=True) \
        .range(offset, offset + limit - 1)

    if category:
        query = query.eq('category', category)

    response = query.execute()
    return jsonify(response.data)


@app.route('/api/jobs', methods=['POST'])
@require_auth
def create_job():
    data = request.json
    required = ['title', 'description', 'budget', 'category', 'poster_name', 'poster_email']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    job = {
        'user_id': request.user.get('sub'),
        'title': data['title'],
        'description': data['description'],
        'budget': data['budget'],
        'category': data['category'],
        'poster_name': data['poster_name'],
        'poster_email': data['poster_email'],
        'timeline': data.get('timeline'),
        'status': 'open'
    }
    result = supabase.table('jobs').insert(job).execute()
    return jsonify(result.data[0]), 201


# ---------- PROPOSALS ----------

@app.route('/api/jobs/<job_id>/proposals', methods=['POST'])
@require_auth
def create_proposal(job_id):
    data = request.json
    required = ['message', 'rate']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    proposal = {
        'job_id': job_id,
        'provider_id': request.user.get('sub'),
        'provider_name': data.get('provider_name', ''),
        'provider_email': data.get('provider_email', ''),
        'message': data['message'],
        'rate': data['rate']
    }
    result = supabase.table('proposals').insert(proposal).execute()
    return jsonify(result.data[0]), 201


@app.route('/api/proposals', methods=['GET'])
@require_auth
def list_my_proposals():
    response = supabase.table('proposals') \
        .select('*, jobs(title, status)') \
        .eq('provider_id', request.user.get('sub')) \
        .order('created_at', desc=True) \
        .execute()
    return jsonify(response.data)


# ---------- PROVIDER APPLICATIONS ----------

@app.route('/api/provider-applications', methods=['POST'])
@require_auth
def apply_as_provider():
    data = request.json
    required = ['full_name', 'email', 'specialty']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    application = {
        'user_id': request.user.get('sub'),
        'full_name': data['full_name'],
        'email': data['email'],
        'specialty': data['specialty'],
        'tools': data.get('tools'),
        'starting_rate': data.get('starting_rate'),
        'portfolio': data.get('portfolio')
    }
    result = supabase.table('provider_applications').insert(application).execute()
    return jsonify(result.data[0]), 201


# ---------- PROFILES ----------

@app.route('/api/profiles/<user_id>', methods=['GET'])
def get_profile(user_id):
    response = supabase.table('profiles').select('*').eq('id', user_id).execute()
    if not response.data:
        return jsonify({"error": "Profile not found"}), 404
    return jsonify(response.data[0])


@app.route('/api/profiles', methods=['PUT'])
@require_auth
def update_profile():
    data = request.json
    result = supabase.table('profiles') \
        .update(data) \
        .eq('id', request.user.get('sub')) \
        .execute()
    return jsonify(result.data[0])


# ---------- CLIENT JOB MANAGEMENT ----------

@app.route('/api/jobs/<job_id>/close', methods=['PUT'])
@require_auth
def close_job(job_id):
    job = supabase.table('jobs').select('user_id').eq('id', job_id).execute()
    if not job.data:
        return jsonify({"error": "Job not found"}), 404
    if job.data[0]['user_id'] != request.user.get('sub'):
        return jsonify({"error": "Forbidden — only the job poster can close this job"}), 403
    result = supabase.table('jobs').update({'status': 'closed'}).eq('id', job_id).execute()
    return jsonify(result.data[0])


@app.route('/api/proposals/<proposal_id>/accept', methods=['PUT'])
@require_auth
def accept_proposal(proposal_id):
    proposal = supabase.table('proposals') \
        .select('*, jobs(user_id)') \
        .eq('id', proposal_id) \
        .execute()
    if not proposal.data:
        return jsonify({"error": "Proposal not found"}), 404
    if proposal.data[0]['jobs']['user_id'] != request.user.get('sub'):
        return jsonify({"error": "Forbidden — only the job poster can accept proposals"}), 403
    result = supabase.table('proposals').update({'status': 'accepted'}).eq('id', proposal_id).execute()
    return jsonify(result.data[0])


# ---------- ADMIN ----------

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.user.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


@app.route('/api/admin/provider-applications/<app_id>', methods=['PUT'])
@require_auth
@require_admin
def review_provider_application(app_id):
    data = request.json
    status = data.get('status')
    if status not in ('approved', 'rejected'):
        return jsonify({"error": "Status must be 'approved' or 'rejected'"}), 400
    result = supabase.table('provider_applications').update({'status': status}).eq('id', app_id).execute()
    if not result.data:
        return jsonify({"error": "Application not found"}), 404
    return jsonify(result.data[0])


# ---------- PAYMENTS ----------

@app.route('/api/payments/create-checkout-session', methods=['POST'])
@require_auth
def create_checkout_session():
    data = request.json
    proposal_id = data.get('proposal_id')
    if not proposal_id:
        return jsonify({"error": "proposal_id required"}), 400

    proposal = supabase.table('proposals') \
        .select('rate, jobs(title)') \
        .eq('id', proposal_id) \
        .execute()
    if not proposal.data:
        return jsonify({"error": "Proposal not found"}), 404

    rate = proposal.data[0]['rate']
    title = proposal.data[0]['jobs']['title']

    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'usd',
                'unit_amount': int(float(rate) * 100),
                'product_data': {'name': f"AXON Escrow: {title}"},
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url=os.getenv("FRONTEND_URL", "http://localhost:3000") + '/success',
        cancel_url=os.getenv("FRONTEND_URL", "http://localhost:3000") + '/cancel',
    )
    return jsonify({"checkout_url": session.url})


# ---------- HEALTH ----------

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "online", "service": "AXON API"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)))
