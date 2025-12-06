"""
DoS Attack Demo Module

This module provides the demo function for DoS attack demonstrations.
It integrates with the attack lab API endpoints.
"""

import os
import sys
import time
import threading
from typing import Dict, Any, List

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_lab.dos.attack import DoSAttacker


def run_demo(with_defense: bool = False) -> Dict[str, Any]:
    """
    Run DoS attack demonstration with optional defense.
    
    Args:
        with_defense: If True, demonstrates defense mechanisms.
    
    Returns:
        dict: Complete demo results with steps, logs, and summary.
    """
    attacker = DoSAttacker()
    
    if with_defense:
        return _run_defended_demo(attacker)
    else:
        return _run_vulnerable_demo(attacker)


def _run_vulnerable_demo(attacker: DoSAttacker) -> Dict[str, Any]:
    """Run DoS attack demo without defenses."""
    steps = []
    logs = []
    
    def log(level: str, message: str):
        logs.append({
            "timestamp": time.time(),
            "level": level,
            "message": message
        })
    
    # Step 1: Setup
    log("info", "Setting up server with no rate limiting...")
    steps.append({
        "step": 1,
        "action": "Setup vulnerable server",
        "result": "No rate limiting or request validation"
    })
    log("info", "Server ready to accept unlimited requests")
    
    # Step 2: Normal traffic
    log("info", "Normal user traffic begins...")
    steps.append({
        "step": 2,
        "action": "Normal users access server",
        "result": "Server handles normal load efficiently"
    })
    log("info", "Server responding to legitimate requests")
    
    # Step 3: Attacker begins DoS attack
    log("warn", "Eve begins DoS attack...")
    steps.append({
        "step": 3,
        "action": "Eve launches DoS attack",
        "result": "Massive flood of requests sent to server"
    })
    log("warn", "DoS attack initiated")
    
    # Step 4: Server becomes overwhelmed
    log("error", "Server resources become overwhelmed...")
    steps.append({
        "step": 4,
        "action": "Server overwhelmed by requests",
        "result": "Response times increase dramatically"
    })
    log("error", "Server struggling to handle load")
    
    # Step 5: Server becomes unresponsive
    log("error", "Server becomes unresponsive to legitimate users...")
    steps.append({
        "step": 5,
        "action": "Server crashes or becomes unresponsive",
        "result": "ATTACK SUCCESS: Service unavailable!"
    })
    log("error", "DoS attack successful - service down")
    
    # Step 6: Show attack statistics
    log("error", "Attack statistics: 1000+ requests per second...")
    steps.append({
        "step": 6,
        "action": "Show attack impact",
        "result": "1000+ RPS, 100% CPU usage, service down"
    })
    log("error", "Massive resource consumption detected")
    
    return {
        "attack_type": "dos",
        "with_defense": False,
        "steps": steps,
        "logs": logs,
        "attack_success": True,
        "summary": (
            "DoS attack successful! The attacker flooded the server with "
            "thousands of requests per second, overwhelming its resources. "
            "Without rate limiting or request validation, the server could "
            "not distinguish between legitimate and malicious traffic. "
            "This caused the server to become unresponsive, denying service "
            "to legitimate users. Common DoS techniques include SYN floods, "
            "HTTP floods, and amplification attacks."
        ),
        "attack_statistics": {
            "requests_per_second": 1000,
            "attack_duration": "30 seconds",
            "server_response_time": "10+ seconds before timeout",
            "cpu_usage": "100%",
            "memory_usage": "Critical"
        },
        "impact": "Complete service unavailability"
    }


def _run_defended_demo(attacker: DoSAttacker) -> Dict[str, Any]:
    """Run DoS attack demo with defenses."""
    steps = []
    logs = []
    
    def log(level: str, message: str):
        logs.append({
            "timestamp": time.time(),
            "level": level,
            "message": message
        })
    
    # Step 1: Setup with rate limiting
    log("info", "Setting up server with rate limiting and DoS protection...")
    steps.append({
        "step": 1,
        "action": "Setup defended server",
        "result": "Token bucket rate limiting enabled"
    })
    log("info", "Rate limiting: 100 requests per minute per IP")
    
    # Step 2: Normal traffic
    log("info", "Normal user traffic begins...")
    steps.append({
        "step": 2,
        "action": "Normal users access server",
        "result": "Server handles normal load with rate limiting"
    })
    log("info", "Legitimate requests processed normally")
    
    # Step 3: Attacker begins DoS attack
    log("warn", "Eve begins DoS attack...")
    steps.append({
        "step": 3,
        "action": "Eve launches DoS attack",
        "result": "Massive flood of requests sent to server"
    })
    log("warn", "DoS attack detected")
    
    # Step 4: Rate limiting activates
    log("info", "Rate limiting activates and blocks excessive requests...")
    steps.append({
        "step": 4,
        "action": "Rate limiting blocks malicious traffic",
        "result": "Excessive requests from Eve are blocked"
    })
    log("info", "Rate limiter blocking attack traffic")
    
    # Step 5: Server continues serving legitimate users
    log("info", "Server continues serving legitimate users normally...")
    steps.append({
        "step": 5,
        "action": "Server maintains service for legitimate users",
        "result": "DEFENSE SUCCESS: Service remains available!"
    })
    log("info", "Legitimate users unaffected by attack")
    
    # Step 6: Attack statistics
    log("info", "Attack statistics: 1000+ RPS blocked by rate limiter...")
    steps.append({
        "step": 6,
        "action": "Show defense effectiveness",
        "result": "1000+ RPS blocked, legitimate users unaffected"
    })
    log("info", "Attack completely mitigated")
    
    # Step 7: Additional defenses
    log("info", "Additional DoS protections active...")
    steps.append({
        "step": 7,
        "action": "Additional protections active",
        "result": "Connection limits, request timeouts, load balancing"
    })
    log("info", "Multiple layers of DoS protection")
    
    return {
        "attack_type": "dos",
        "with_defense": True,
        "steps": steps,
        "logs": logs,
        "attack_success": False,
        "summary": (
            "DoS attack blocked! The defended server uses multiple layers "
            "of protection including token bucket rate limiting, connection "
            "limits, and request timeouts. When the attacker flooded the "
            "server with requests, the rate limiter immediately blocked "
            "excessive traffic from the attacking IP. Legitimate users "
            "continued to receive normal service without any impact. "
            "Additional protections like load balancing and CDN services "
            "would provide even stronger defense against distributed attacks."
        ),
        "defense_mechanisms": [
            "Token bucket rate limiting (100 RPM per IP)",
            "Connection limits per IP address",
            "Request timeout enforcement",
            "Load balancing (conceptual)",
            "Traffic filtering and monitoring"
        ],
        "attack_blocked": 1000,
        "legitimate_users_served": "100%",
        "damage_prevented": "Service downtime, financial loss, reputation damage"
    }


if __name__ == "__main__":
    print("DoS Attack Demo Module")
    print("Use run_demo(with_defense=True/False) to run demonstrations")
