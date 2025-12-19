from flask import Blueprint, request, jsonify
from security import (
    hash_password_func,
    generate_password_func,
    check_password_strength_func,
    validate_email_func,
)
from virus_total import (
    virus_total_scan,
    submit_url_to_virustotal,
    get_url_report_from_virustotal,
)

api_blueprint = Blueprint("api", __name__)

@api_blueprint.route("/api/hash", methods=["POST"])
def hash_password():
    data = request.get_json()
    return jsonify(hash_password_func(data))

@api_blueprint.route("/api/generate-password", methods=["POST"])
def generate_password():
    data = request.get_json()
    return jsonify(generate_password_func(data))

@api_blueprint.route("/api/check-strength", methods=["POST"])
def check_strength():
    data = request.get_json()
    return jsonify(check_password_strength_func(data))

@api_blueprint.route("/api/validate-email", methods=["POST"])
def validate_email():
    data = request.get_json()
    return jsonify(validate_email_func(data))

@api_blueprint.route("/api/virus-total", methods=["POST"])
def virus_total():
    data = request.get_json()
    return jsonify(virus_total_scan(data))

@api_blueprint.route("/api/virus-total/submit", methods=["POST"])
def virus_total_submit():
    data = request.get_json()
    return jsonify(submit_url_to_virustotal(data))

@api_blueprint.route("/api/virus-total/report", methods=["POST"])
def virus_total_report():
    data = request.get_json()
    return jsonify(get_url_report_from_virustotal(data))