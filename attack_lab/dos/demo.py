"""
Denial of Service Attack Interactive Demo

This module provides a complete interactive demonstration of:
1. How DoS attacks work by overwhelming server resources
2. How token bucket rate limiting defends against DoS attacks

Run this demo directly:
    python -m attack_lab.dos.demo
"""

import os
import sys
import time
from datetime import datetime
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from attack_lab.dos.attack import DoSAttacker
from attack_lab.dos.defense import DoSDefense


def run_demo(with_defense: bool = False) -> Dict[str, Any]:
    """
    Run the DoS attack demonstration.
    
    Args:
        with_defense: If True, enable rate limiting defense.
    
    Returns:
        dict: Demo results with steps, logs, and outcome.
    """
    steps = []
    logs = []
    
    def log(level: str, message: str):
        logs.append({
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        })
    
    def add_step(step_num: int, action: str, result: str):
        steps.append({
            "step": step_num,
            "action": action,
            "result": result
        })
    
    # Initialize components
    attacker = DoSAttacker("/api/register")
    defense = DoSDefense(rate=10.0, burst=20) if with_defense else None
    attacker_ip = "10.0.0.99"
    legitimate_ip = "192.168.1.100"
    
    log("info", f"Starting DoS attack demo (defense: {'enabled' if with_defense else 'disabled'})")
    
    # Step 1: Measure baseline performance
    log("info", "Measuring baseline server performance...")
    
    baseline_times = []
    for i in range(5):
        start = time.time()
        time.sleep(0.005)  # Simulate normal request
        baseline_times.append(time.time() - start)
    
    avg_baseline = sum(baseline_times) / len(baseline_times)
    
    add_step(1, "Measure baseline performance",
             f"Average response time: {avg_baseline*1000:.2f}ms")
    
    # Step 2: Launch DoS attack
    log("error", f"Attacker launching DoS flood from {attacker_ip}...")
    
    attack_results = {
        "allowed": 0,
        "blocked": 0,
        "response_times": []
    }
    
    attack_requests = attacker.generate_flood_requests(100)
    
    if with_defense:
        # Process through rate limiter
        for request in attack_requests:
            start = time.time()
            result = defense.process_request(attacker_ip, request)
            elapsed = time.time() - start
            
            if result["success"]:
                attack_results["allowed"] += 1
            else:
                attack_results["blocked"] += 1
            attack_results["response_times"].append(elapsed)
        
        add_step(2, f"Process 100 attack requests through rate limiter",
                 f"Allowed: {attack_results['allowed']}, Blocked: {attack_results['blocked']}")
        
        log("info", f"Rate limiter blocked {attack_results['blocked']} of 100 requests")
    else:
        # No rate limiting - all requests processed
        for request in attack_requests:
            start = time.time()
            time.sleep(0.005)  # Simulate processing
            elapsed = time.time() - start
            attack_results["allowed"] += 1
            attack_results["response_times"].append(elapsed)
        
        add_step(2, "Process 100 attack requests (no rate limiting)",
                 f"All 100 requests processed - server overwhelmed!")
        
        log("error", "Server processed all attack requests - resources exhausted!")
    
    # Step 3: Test legitimate user during attack
    log("info", f"Testing legitimate user from {legitimate_ip} during attack...")
    
    legit_results = {
        "allowed": 0,
        "blocked": 0,
        "response_times": []
    }
    
    for i in range(5):
        start = time.time()
        
        if with_defense:
            result = defense.process_request(legitimate_ip, {"id": i})
            if result["success"]:
                legit_results["allowed"] += 1
            else:
                legit_results["blocked"] += 1
        else:
            # Without defense, legitimate users suffer degraded service
            time.sleep(0.02)  # Simulated degraded response
            legit_results["allowed"] += 1
        
        legit_results["response_times"].append(time.time() - start)
    
    avg_legit_time = sum(legit_results["response_times"]) / len(legit_results["response_times"])
    
    if with_defense:
        add_step(3, f"Test legitimate user (5 requests from {legitimate_ip})",
                 f"All {legit_results['allowed']}/5 allowed, avg time: {avg_legit_time*1000:.2f}ms")
    else:
        degradation = (avg_legit_time - avg_baseline) / avg_baseline * 100
        add_step(3, "Test legitimate user during attack",
                 f"Requests processed but degraded: {degradation:.1f}% slower")
    
    # Step 4: Calculate attack impact
    attack_success = False
    
    if with_defense:
        block_rate = attack_results["blocked"] / 100 * 100
        
        add_step(4, "Calculate defense effectiveness",
                 f"Blocked {block_rate:.1f}% of attack, legitimate users unaffected")
        
        if block_rate > 50:
            attack_success = False
            log("info", "DoS attack mitigated by rate limiting!")
        else:
            attack_success = True
            log("error", "Rate limiting not effective enough!")
    else:
        # Calculate service degradation
        degradation_pct = (avg_legit_time - avg_baseline) / avg_baseline * 100
        
        add_step(4, "Calculate attack impact",
                 f"Service degraded by {degradation_pct:.1f}% for all users")
        
        attack_success = True
        log("error", f"DoS attack successful - service degraded by {degradation_pct:.1f}%!")
    
    # Summary
    if with_defense:
        if attack_success:
            summary = (
                "DEFENSE PARTIALLY EFFECTIVE: Rate limiting blocked some requests "
                "but the attack still caused service degradation. Consider adjusting "
                "rate limits or adding additional defense layers."
            )
        else:
            stats = defense.get_stats()
            summary = (
                f"DEFENSE SUCCESSFUL: Rate limiting blocked {stats['blocked']} of "
                f"{stats['total_requests']} attack requests ({stats['block_rate']*100:.1f}%). "
                f"Legitimate users from other IPs were able to access the service normally. "
                f"The per-IP rate limiting isolates attackers without affecting good traffic."
            )
    else:
        summary = (
            f"ATTACK SUCCESSFUL: Without rate limiting, the attacker sent {attack_results['allowed']} "
            f"requests that consumed server resources. Legitimate users experienced "
            f"significant service degradation. The server had no way to distinguish "
            f"attack traffic from legitimate traffic."
        )
    
    result_data = {
        "attack_type": "dos",
        "with_defense": with_defense,
        "steps": steps,
        "logs": logs,
        "attack_success": attack_success,
        "summary": summary,
        "attack_stats": {
            "total_requests": 100,
            "allowed": attack_results["allowed"],
            "blocked": attack_results["blocked"],
            "avg_response_time": sum(attack_results["response_times"]) / len(attack_results["response_times"]) * 1000
        },
        "legitimate_user_stats": {
            "requests": 5,
            "allowed": legit_results["allowed"],
            "avg_response_time": avg_legit_time * 1000
        },
        "baseline_response_time": avg_baseline * 1000,
        "defense_status": "enabled" if with_defense else "disabled"
    }
    
    if with_defense:
        result_data["defense_stats"] = defense.get_stats()
    
    return result_data


def main():
    """Run the demo with both modes and display results."""
    print("=" * 70)
    print("               DENIAL OF SERVICE ATTACK DEMONSTRATION")
    print("=" * 70)
    
    # Run without defense
    print("\n" + "-" * 70)
    print("SCENARIO 1: Vulnerable System (No Rate Limiting)")
    print("-" * 70)
    
    result = run_demo(with_defense=False)
    
    print("\n--- Steps ---")
    for step in result["steps"]:
        print(f"\n  Step {step['step']}: {step['action']}")
        print(f"    → {step['result']}")
    
    print("\n--- Event Log ---")
    for log in result["logs"]:
        level_icon = {"info": "ℹ", "warn": "⚠", "error": "✖"}.get(log["level"], "•")
        print(f"  {level_icon} [{log['level'].upper()}] {log['message']}")
    
    print("\n--- Attack Statistics ---")
    stats = result["attack_stats"]
    print(f"  Requests sent: {stats['total_requests']}")
    print(f"  Requests processed: {stats['allowed']}")
    print(f"  Avg response time: {stats['avg_response_time']:.2f}ms")
    
    print("\n--- Legitimate User Impact ---")
    legit = result["legitimate_user_stats"]
    baseline = result["baseline_response_time"]
    degradation = (legit["avg_response_time"] - baseline) / baseline * 100
    print(f"  Baseline response: {baseline:.2f}ms")
    print(f"  During attack: {legit['avg_response_time']:.2f}ms")
    print(f"  Degradation: {degradation:.1f}%")
    
    print(f"\n📋 RESULT: Attack {'SUCCEEDED' if result['attack_success'] else 'FAILED'}")
    print(f"\n{result['summary']}")
    
    # Run with defense
    print("\n" + "-" * 70)
    print("SCENARIO 2: Protected System (Token Bucket Rate Limiting)")
    print("-" * 70)
    
    result = run_demo(with_defense=True)
    
    print("\n--- Steps ---")
    for step in result["steps"]:
        print(f"\n  Step {step['step']}: {step['action']}")
        print(f"    → {step['result']}")
    
    print("\n--- Event Log ---")
    for log in result["logs"]:
        level_icon = {"info": "ℹ", "warn": "⚠", "error": "✖"}.get(log["level"], "•")
        print(f"  {level_icon} [{log['level'].upper()}] {log['message']}")
    
    print("\n--- Defense Statistics ---")
    if "defense_stats" in result:
        stats = result["defense_stats"]
        print(f"  Total requests: {stats['total_requests']}")
        print(f"  Allowed: {stats['allowed']}")
        print(f"  Blocked: {stats['blocked']}")
        print(f"  Block rate: {stats['block_rate']*100:.1f}%")
        print(f"  Tracked IPs: {stats['tracked_ips']}")
    
    print("\n--- Legitimate User Status ---")
    legit = result["legitimate_user_stats"]
    print(f"  Requests: {legit['requests']}")
    print(f"  Allowed: {legit['allowed']}")
    print(f"  Avg response: {legit['avg_response_time']:.2f}ms")
    
    print(f"\n📋 RESULT: Attack {'SUCCEEDED' if result['attack_success'] else 'BLOCKED'}")
    print(f"\n{result['summary']}")
    
    # Final comparison
    print("\n" + "=" * 70)
    print("                         COMPARISON")
    print("=" * 70)
    print("""
    ┌─────────────────────────────────────────────────────────────────┐
    │                  WITHOUT RATE LIMITING                          │
    ├─────────────────────────────────────────────────────────────────┤
    │  • All requests processed regardless of source                  │
    │  • Single attacker can exhaust server resources                 │
    │  • Legitimate users experience service degradation              │
    │  • No way to distinguish attack from legitimate traffic         │
    │  • Result: SERVICE DENIAL FOR ALL USERS                         │
    └─────────────────────────────────────────────────────────────────┘
    
    ┌─────────────────────────────────────────────────────────────────┐
    │                  WITH TOKEN BUCKET RATE LIMITING                │
    ├─────────────────────────────────────────────────────────────────┤
    │  • Each IP has separate rate limit (token bucket)               │
    │  • Burst traffic allowed up to bucket capacity                  │
    │  • Sustained attacks blocked after bucket depleted              │
    │  • Legitimate users unaffected (different buckets)              │
    │  • Result: ATTACK MITIGATED, SERVICE PRESERVED                  │
    └─────────────────────────────────────────────────────────────────┘
    
    Key Insight: Per-IP rate limiting isolates attackers and protects
    service availability for legitimate users. Token bucket algorithm
    allows short bursts while preventing sustained floods.
    """)
    print("=" * 70)


if __name__ == "__main__":
    main()