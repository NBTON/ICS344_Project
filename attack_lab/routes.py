"""
Attack Lab API Routes

This module provides Flask API endpoints for running attack demonstrations.
Each endpoint accepts a JSON body with 'with_defense' boolean to toggle
between vulnerable and defended modes.

API Endpoints:
- POST /api/attack-lab/replay    - Run replay attack demo
- POST /api/attack-lab/tampering - Run ciphertext tampering demo
- POST /api/attack-lab/mitm      - Run MITM attack demo
- POST /api/attack-lab/dos       - Run DoS attack demo
- GET  /api/attack-lab/status    - Get attack lab status
"""

import os
import sys
from flask import Blueprint, jsonify, request

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import demo modules
from attack_lab.replay import demo as replay_demo
from attack_lab.tampering import demo as tampering_demo
from attack_lab.mitm import demo as mitm_demo
from attack_lab.dos import demo as dos_demo


# Create Blueprint
attack_lab_bp = Blueprint('attack_lab', __name__, url_prefix='/api/attack-lab')


@attack_lab_bp.route('/status', methods=['GET'])
def get_status():
    """
    Get Attack Lab status and available attacks.
    
    Returns:
        JSON with available attack types and their descriptions.
    """
    return jsonify({
        "status": "ready",
        "version": "1.0.0",
        "attacks": {
            "replay": {
                "name": "Replay Attack",
                "description": "Demonstrates capturing and resending valid encrypted messages",
                "endpoint": "/api/attack-lab/replay",
                "defense": "Timestamp + Nonce validation"
            },
            "tampering": {
                "name": "Ciphertext Tampering",
                "description": "Demonstrates modifying encrypted data in transit",
                "endpoint": "/api/attack-lab/tampering",
                "defense": "AES-GCM authentication tag"
            },
            "mitm": {
                "name": "Man-in-the-Middle",
                "description": "Demonstrates intercepting and manipulating key exchanges",
                "endpoint": "/api/attack-lab/mitm",
                "defense": "RSA-PSS digital signatures"
            },
            "dos": {
                "name": "Denial of Service",
                "description": "Demonstrates flooding server with requests",
                "endpoint": "/api/attack-lab/dos",
                "defense": "Token bucket rate limiting"
            }
        }
    })


@attack_lab_bp.route('/replay', methods=['POST'])
def run_replay_attack():
    """
    Run replay attack demonstration.
    
    Request Body:
        with_defense (bool): Enable/disable replay protection (default: False)
    
    Returns:
        JSON with attack results, steps, logs, and summary.
    """
    try:
        data = request.get_json() or {}
        with_defense = data.get('with_defense', False)
        
        result = replay_demo.run_demo(with_defense=with_defense)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "attack_type": "replay",
            "success": False
        }), 500


@attack_lab_bp.route('/tampering', methods=['POST'])
def run_tampering_attack():
    """
    Run ciphertext tampering attack demonstration.
    
    Request Body:
        with_defense (bool): Enable/disable GCM authentication (default: False)
    
    Returns:
        JSON with attack results, steps, logs, and summary.
    """
    try:
        data = request.get_json() or {}
        with_defense = data.get('with_defense', False)
        
        result = tampering_demo.run_demo(with_defense=with_defense)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "attack_type": "tampering",
            "success": False
        }), 500


@attack_lab_bp.route('/mitm', methods=['POST'])
def run_mitm_attack():
    """
    Run Man-in-the-Middle attack demonstration.
    
    Request Body:
        with_defense (bool): Enable/disable signature verification (default: False)
    
    Returns:
        JSON with attack results, steps, logs, and summary.
    """
    try:
        data = request.get_json() or {}
        with_defense = data.get('with_defense', False)
        
        result = mitm_demo.run_demo(with_defense=with_defense)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "attack_type": "mitm",
            "success": False
        }), 500


@attack_lab_bp.route('/dos', methods=['POST'])
def run_dos_attack():
    """
    Run Denial of Service attack demonstration.
    
    Request Body:
        with_defense (bool): Enable/disable rate limiting (default: False)
    
    Returns:
        JSON with attack results, steps, logs, and summary.
    """
    try:
        data = request.get_json() or {}
        with_defense = data.get('with_defense', False)
        
        result = dos_demo.run_demo(with_defense=with_defense)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "attack_type": "dos",
            "success": False
        }), 500


@attack_lab_bp.route('/run-all', methods=['POST'])
def run_all_attacks():
    """
    Run all attack demonstrations.
    
    Request Body:
        with_defense (bool): Enable/disable defenses for all attacks (default: False)
    
    Returns:
        JSON with results from all four attack demonstrations.
    """
    try:
        data = request.get_json() or {}
        with_defense = data.get('with_defense', False)
        
        results = {
            "replay": replay_demo.run_demo(with_defense=with_defense),
            "tampering": tampering_demo.run_demo(with_defense=with_defense),
            "mitm": mitm_demo.run_demo(with_defense=with_defense),
            "dos": dos_demo.run_demo(with_defense=with_defense)
        }
        
        # Calculate summary
        attacks_succeeded = sum(
            1 for r in results.values() if r.get("attack_success", False)
        )
        
        return jsonify({
            "with_defense": with_defense,
            "results": results,
            "summary": {
                "total_attacks": 4,
                "attacks_succeeded": attacks_succeeded,
                "attacks_blocked": 4 - attacks_succeeded,
                "defense_effective": attacks_succeeded == 0 if with_defense else None
            }
        })
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "success": False
        }), 500


@attack_lab_bp.route('/compare/<attack_type>', methods=['GET'])
def compare_attack(attack_type: str):
    """
    Run an attack with and without defense and compare results.
    
    Args:
        attack_type: One of 'replay', 'tampering', 'mitm', 'dos'
    
    Returns:
        JSON with side-by-side comparison of vulnerable vs defended.
    """
    try:
        demo_map = {
            'replay': replay_demo,
            'tampering': tampering_demo,
            'mitm': mitm_demo,
            'dos': dos_demo
        }
        
        if attack_type not in demo_map:
            return jsonify({
                "error": f"Unknown attack type: {attack_type}",
                "valid_types": list(demo_map.keys())
            }), 400
        
        demo = demo_map[attack_type]
        
        # Run both scenarios
        vulnerable_result = demo.run_demo(with_defense=False)
        defended_result = demo.run_demo(with_defense=True)
        
        return jsonify({
            "attack_type": attack_type,
            "vulnerable": {
                "attack_success": vulnerable_result.get("attack_success"),
                "summary": vulnerable_result.get("summary"),
                "steps": vulnerable_result.get("steps")
            },
            "defended": {
                "attack_success": defended_result.get("attack_success"),
                "summary": defended_result.get("summary"),
                "steps": defended_result.get("steps")
            },
            "comparison": {
                "vulnerable_attack_succeeds": vulnerable_result.get("attack_success", False),
                "defended_attack_blocked": not defended_result.get("attack_success", True),
                "defense_effective": (
                    vulnerable_result.get("attack_success", False) and 
                    not defended_result.get("attack_success", True)
                )
            }
        })
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "attack_type": attack_type,
            "success": False
        }), 500


# Error handlers for the blueprint
@attack_lab_bp.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad Request", "message": str(error)}), 400


@attack_lab_bp.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal Server Error", "message": str(error)}), 500