"""
Denial of Service (DoS) Attack Implementation

This module demonstrates how an attacker can flood a server with
requests to exhaust resources and deny service to legitimate users.

DoS Attack Techniques:
1. Volume-based attacks - Flood with massive traffic
2. Protocol attacks - Exploit protocol weaknesses (SYN flood)
3. Application layer attacks - Target specific endpoints

This demo focuses on application layer attacks by generating
many requests to overwhelm the server's processing capacity.
"""

import os
import sys
import time
import random
from typing import Dict, Any, List, Callable, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class DoSAttacker:
    """
    Demonstrates DoS attack by flooding with requests.
    
    The attacker generates a high volume of requests to
    exhaust server resources and degrade service quality.
    """
    
    def __init__(self, target_endpoint: str = "/api/register"):
        """
        Initialize the DoS attacker.
        
        Args:
            target_endpoint: The endpoint to target.
        """
        self.target = target_endpoint
        self.request_count = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.response_times = []
        self.attack_log = []
    
    def _log_attack(self, action: str, details: str = ""):
        """Log an attack action."""
        self.attack_log.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        })
    
    def generate_flood_requests(self, count: int = 100) -> List[Dict[str, Any]]:
        """
        Generate many requests for flooding.
        
        Args:
            count: Number of requests to generate.
        
        Returns:
            list: List of request dictionaries.
        """
        requests = []
        
        for i in range(count):
            # Generate varied request data to avoid caching
            request = {
                "id": i,
                "timestamp": time.time(),
                "endpoint": self.target,
                "method": "POST",
                "data": {
                    "username": f"user_{i}_{random.randint(1000, 9999)}",
                    "email": f"attacker{i}@evil.com",
                    "random_data": os.urandom(100).hex()  # Add payload
                },
                "headers": {
                    "User-Agent": f"DoSBot/{random.randint(1, 100)}",
                    "X-Request-ID": f"attack-{i}-{time.time()}"
                }
            }
            requests.append(request)
        
        self._log_attack(
            "generate_requests",
            f"Generated {count} flood requests for {self.target}"
        )
        
        return requests
    
    def simulate_send_request(self, request: Dict[str, Any],
                              process_func: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Simulate sending a request and measure response time.
        
        Args:
            request: The request to send.
            process_func: Optional function to process the request.
        
        Returns:
            dict: Result of the request.
        """
        start_time = time.time()
        self.request_count += 1
        
        try:
            if process_func:
                # Call the server's processing function
                result = process_func(request)
                success = result.get("success", True)
            else:
                # Simulate processing time
                time.sleep(random.uniform(0.001, 0.01))
                success = True
                result = {"success": True}
            
            elapsed = time.time() - start_time
            self.response_times.append(elapsed)
            
            if success:
                self.successful_requests += 1
            else:
                self.failed_requests += 1
            
            return {
                "request_id": request.get("id"),
                "success": success,
                "response_time": elapsed,
                "status": result.get("status", 200 if success else 429)
            }
            
        except Exception as e:
            self.failed_requests += 1
            return {
                "request_id": request.get("id"),
                "success": False,
                "error": str(e),
                "response_time": time.time() - start_time
            }
    
    def flood_attack(self, request_count: int = 100,
                     process_func: Optional[Callable] = None,
                     concurrent: bool = True,
                     max_workers: int = 10) -> Dict[str, Any]:
        """
        Execute a flood attack.
        
        Args:
            request_count: Number of requests to send.
            process_func: Function to process requests (simulates server).
            concurrent: Whether to send requests concurrently.
            max_workers: Number of concurrent workers.
        
        Returns:
            dict: Attack results and statistics.
        """
        self._log_attack("start_flood", f"Starting flood with {request_count} requests")
        
        # Generate requests
        requests = self.generate_flood_requests(request_count)
        results = []
        
        start_time = time.time()
        
        if concurrent:
            # Send requests concurrently
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self.simulate_send_request, req, process_func): req
                    for req in requests
                }
                
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)
        else:
            # Send requests sequentially
            for request in requests:
                result = self.simulate_send_request(request, process_func)
                results.append(result)
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        stats = self._calculate_attack_stats(results, total_time)
        
        self._log_attack(
            "flood_complete",
            f"Sent {request_count} requests in {total_time:.2f}s"
        )
        
        return {
            "total_requests": request_count,
            "successful": self.successful_requests,
            "failed": self.failed_requests,
            "total_time": total_time,
            "requests_per_second": request_count / total_time if total_time > 0 else 0,
            "stats": stats,
            "results": results[:10]  # First 10 for display
        }
    
    def _calculate_attack_stats(self, results: List[Dict], total_time: float) -> Dict[str, Any]:
        """Calculate attack statistics."""
        response_times = [r.get("response_time", 0) for r in results if r.get("response_time")]
        
        if not response_times:
            return {}
        
        return {
            "min_response_time": min(response_times),
            "max_response_time": max(response_times),
            "avg_response_time": sum(response_times) / len(response_times),
            "total_time": total_time,
            "success_rate": self.successful_requests / len(results) if results else 0,
            "blocked_rate": self.failed_requests / len(results) if results else 0
        }
    
    def measure_service_degradation(self, baseline_time: float,
                                    during_attack_times: List[float]) -> Dict[str, Any]:
        """
        Measure how much the attack degrades service.
        
        Args:
            baseline_time: Normal response time without attack.
            during_attack_times: Response times during attack.
        
        Returns:
            dict: Degradation metrics.
        """
        if not during_attack_times:
            return {"degradation": 0}
        
        avg_attack_time = sum(during_attack_times) / len(during_attack_times)
        degradation = (avg_attack_time - baseline_time) / baseline_time * 100
        
        return {
            "baseline_response_time": baseline_time,
            "avg_attack_response_time": avg_attack_time,
            "degradation_percent": degradation,
            "slowdown_factor": avg_attack_time / baseline_time if baseline_time > 0 else float('inf')
        }
    
    def get_attack_log(self) -> List[Dict[str, Any]]:
        """Get the attack log."""
        return self.attack_log.copy()
    
    def reset_stats(self):
        """Reset attack statistics."""
        self.request_count = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.response_times.clear()
        self.attack_log.clear()
    
    def demonstrate_attack(self, rate_limit_enabled: bool = False) -> Dict[str, Any]:
        """
        Run a full DoS attack demonstration.
        
        Args:
            rate_limit_enabled: Whether rate limiting is active.
        
        Returns:
            dict: Results of the attack demonstration.
        """
        steps = []
        logs = []
        
        def log(level: str, message: str):
            logs.append({
                "timestamp": datetime.now().isoformat(),
                "level": level,
                "message": message
            })
        
        self.reset_stats()
        
        # Step 1: Measure baseline response time
        log("info", "Measuring baseline server response time...")
        baseline_start = time.time()
        time.sleep(0.01)  # Simulate normal request
        baseline_time = time.time() - baseline_start
        
        steps.append({
            "step": 1,
            "action": "Measure baseline performance",
            "result": f"Normal response time: {baseline_time*1000:.2f}ms"
        })
        
        # Step 2: Launch flood attack
        log("error", f"Launching DoS attack with 100 requests...")
        
        def vulnerable_server(request):
            """Simulate a server without rate limiting."""
            time.sleep(0.005)  # Simulate processing
            return {"success": True, "status": 200}
        
        flood_results = self.flood_attack(
            request_count=100,
            process_func=vulnerable_server,
            concurrent=True,
            max_workers=20
        )
        
        steps.append({
            "step": 2,
            "action": "Launch flood attack (100 requests)",
            "result": f"Sent at {flood_results['requests_per_second']:.1f} req/s"
        })
        
        # Step 3: Measure impact on legitimate users
        log("warn", "Measuring impact on legitimate users...")
        
        # Simulate legitimate user during attack
        legit_times = []
        for _ in range(5):
            start = time.time()
            time.sleep(0.02)  # Degraded response due to load
            legit_times.append(time.time() - start)
        
        degradation = self.measure_service_degradation(baseline_time, legit_times)
        
        steps.append({
            "step": 3,
            "action": "Measure service degradation",
            "result": f"Response time increased by {degradation['degradation_percent']:.1f}%"
        })
        
        # Step 4: Report results
        log("error", "Attack complete - server overwhelmed!")
        
        steps.append({
            "step": 4,
            "action": "Attack results",
            "result": f"{flood_results['successful']} requests processed, "
                     f"service degraded for legitimate users"
        })
        
        return {
            "attack_type": "dos",
            "with_defense": False,
            "steps": steps,
            "logs": logs,
            "attack_success": True,
            "summary": (
                f"DoS attack successful! Sent {flood_results['total_requests']} requests "
                f"at {flood_results['requests_per_second']:.1f} requests/second. "
                f"Server was overwhelmed and legitimate users experienced "
                f"{degradation['degradation_percent']:.1f}% slower response times."
            ),
            "flood_stats": flood_results["stats"],
            "degradation": degradation,
            "total_requests": flood_results["total_requests"]
        }


if __name__ == "__main__":
    print("=" * 60)
    print("DENIAL OF SERVICE ATTACK DEMONSTRATION")
    print("=" * 60)
    
    attacker = DoSAttacker("/api/register")
    result = attacker.demonstrate_attack(rate_limit_enabled=False)
    
    print("\n--- Attack Steps ---")
    for step in result["steps"]:
        print(f"\nStep {step['step']}: {step['action']}")
        print(f"  Result: {step['result']}")
    
    print("\n--- Attack Statistics ---")
    stats = result.get("flood_stats", {})
    print(f"  Min response time: {stats.get('min_response_time', 0)*1000:.2f}ms")
    print(f"  Max response time: {stats.get('max_response_time', 0)*1000:.2f}ms")
    print(f"  Avg response time: {stats.get('avg_response_time', 0)*1000:.2f}ms")
    print(f"  Success rate: {stats.get('success_rate', 0)*100:.1f}%")
    
    print("\n--- Service Degradation ---")
    deg = result.get("degradation", {})
    print(f"  Baseline: {deg.get('baseline_response_time', 0)*1000:.2f}ms")
    print(f"  During attack: {deg.get('avg_attack_response_time', 0)*1000:.2f}ms")
    print(f"  Degradation: {deg.get('degradation_percent', 0):.1f}%")
    
    print("\n" + "=" * 60)
    print("SUMMARY:", result["summary"])
    print("=" * 60)