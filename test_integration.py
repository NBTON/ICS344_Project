#!/usr/bin/env python3
"""
SecureChat Integration Test Suite

This script tests all components of SecureChat to ensure they work together correctly.
It verifies the complete functionality including cryptography, API endpoints, key management,
WebSocket communication, and Attack Lab demonstrations.

Usage:
    python test_integration.py [--verbose] [--skip-attack-lab] [--host HOST] [--port PORT]
"""

import sys
import os
import time
import json
import requests
import threading
import traceback
from typing import Dict, Any, List, Tuple
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import project modules
from backend.crypto.aes_gcm import generate_key, encrypt, decrypt
from backend.crypto.rsa_keys import generate_key_pair, serialize_public_key, load_public_key
from backend.crypto.rsa_oaep import encrypt_key, decrypt_key
from backend.crypto.rsa_pss import sign, verify
from backend.services.key_manager import get_key_manager
from backend.models.message import Message, MessageFlags


class SecureChatIntegrationTest:
    """Comprehensive integration test for SecureChat."""
    
    def __init__(self, host: str = "localhost", port: int = 5000, verbose: bool = False):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.verbose = verbose
        self.test_results = []
        self.failed_tests = []
        self.passed_tests = []
        
        # Test users
        self.alice = "alice_test_user"
        self.bob = "bob_test_user"
        self.session_id = None
        
        # Test data
        self.test_message = "Hello, SecureChat! This is a test message for integration testing."
        self.test_message_2 = "Second test message to verify multiple message handling."
        
    def log(self, message: str, level: str = "INFO"):
        """Log test progress."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if self.verbose or level in ["ERROR", "FAIL", "PASS"]:
            print(f"[{timestamp}] [{level:5}] {message}")
    
    def run_test(self, test_name: str, test_func) -> bool:
        """Run a single test and track results."""
        self.log(f"Running: {test_name}", "INFO")
        start_time = time.time()
        
        try:
            result = test_func()
            duration = time.time() - start_time
            
            if result:
                self.log(f"PASSED: {test_name} ({duration:.2f}s)", "PASS")
                self.passed_tests.append(test_name)
                self.test_results.append({
                    "test": test_name,
                    "status": "PASS",
                    "duration": duration
                })
                return True
            else:
                self.log(f"FAILED: {test_name} ({duration:.2f}s)", "FAIL")
                self.failed_tests.append(test_name)
                self.test_results.append({
                    "test": test_name,
                    "status": "FAIL",
                    "duration": duration,
                    "error": "Test returned False"
                })
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.log(f"ERROR: {test_name} ({duration:.2f}s) - {str(e)}", "ERROR")
            self.failed_tests.append(test_name)
            self.test_results.append({
                "test": test_name,
                "status": "ERROR",
                "duration": duration,
                "error": str(e),
                "traceback": traceback.format_exc()
            })
            return False
    
    def test_cryptography_modules(self) -> bool:
        """Test all cryptographic modules work correctly."""
        try:
            # Test AES-256-GCM
            key = generate_key()
            plaintext = b"Test message for AES-GCM encryption"
            ciphertext, iv, tag = encrypt(plaintext, key)
            decrypted = decrypt(ciphertext, key, iv, tag)
            assert decrypted == plaintext, "AES-GCM decryption failed"
            
            # Test RSA-OAEP
            private_key, public_key = generate_key_pair()
            session_key = os.urandom(32)
            encrypted_key = encrypt_key(session_key, public_key)
            decrypted_key = decrypt_key(encrypted_key, private_key)
            assert decrypted_key == session_key, "RSA-OAEP decryption failed"
            
            # Test RSA-PSS
            message = b"Test message for RSA-PSS signing"
            signature = sign(message, private_key)
            is_valid = verify(message, signature, public_key)
            assert is_valid, "RSA-PSS signature verification failed"
            
            # Test Message model
            msg = Message(
                version=1,
                flags=MessageFlags.ENCRYPTED | MessageFlags.SIGNED,
                timestamp=int(time.time() * 1000),
                nonce=os.urandom(16),
                sender_id=os.urandom(32),
                iv=os.urandom(12),
                ciphertext=ciphertext,
                auth_tag=tag,
                signature=signature
            )
            serialized = msg.to_bytes()
            deserialized = Message.from_bytes(serialized)
            assert deserialized.ciphertext == msg.ciphertext, "Message serialization failed"
            
            return True
            
        except Exception as e:
            self.log(f"Cryptography test failed: {e}", "ERROR")
            return False
    
    def test_api_health(self) -> bool:
        """Test API endpoints are accessible."""
        try:
            response = requests.get(f"{self.base_url}/api/health", timeout=5)
            assert response.status_code == 200, f"Health check failed: {response.status_code}"
            data = response.json()
            assert "status" in data, "Health check response missing status"
            assert data["status"] == "healthy", f"Service not healthy: {data['status']}"
            return True
            
        except Exception as e:
            self.log(f"API health check failed: {e}", "ERROR")
            return False
    
    def test_user_registration(self) -> bool:
        """Test user registration functionality."""
        try:
            # Register Alice
            response = requests.post(f"{self.base_url}/api/register", 
                                   json={"user_id": self.alice}, timeout=5)
            assert response.status_code == 201, f"Alice registration failed: {response.status_code}"
            alice_data = response.json()
            assert alice_data["user_id"] == self.alice, "Alice registration data incorrect"
            assert "public_key" in alice_data, "Alice public key missing"
            assert "fingerprint" in alice_data, "Alice fingerprint missing"
            
            # Register Bob
            response = requests.post(f"{self.base_url}/api/register", 
                                   json={"user_id": self.bob}, timeout=5)
            assert response.status_code == 201, f"Bob registration failed: {response.status_code}"
            bob_data = response.json()
            assert bob_data["user_id"] == self.bob, "Bob registration data incorrect"
            
            # Test duplicate registration
            response = requests.post(f"{self.base_url}/api/register", 
                                   json={"user_id": self.alice}, timeout=5)
            assert response.status_code == 409, f"Duplicate registration should fail: {response.status_code}"
            
            return True
            
        except Exception as e:
            self.log(f"User registration test failed: {e}", "ERROR")
            return False
    
    def test_key_management(self) -> bool:
        """Test key management functionality."""
        try:
            # Test get users
            response = requests.get(f"{self.base_url}/api/users", timeout=5)
            assert response.status_code == 200, f"Get users failed: {response.status_code}"
            users_data = response.json()
            assert "users" in users_data, "Users list missing"
            assert len(users_data["users"]) >= 2, "Not enough users registered"
            
            # Test get public key
            response = requests.get(f"{self.base_url}/api/keys/public/{self.alice}", timeout=5)
            assert response.status_code == 200, f"Get public key failed: {response.status_code}"
            key_data = response.json()
            assert key_data["user_id"] == self.alice, "Public key data incorrect"
            assert "public_key" in key_data, "Public key missing"
            assert "fingerprint" in key_data, "Fingerprint missing"
            
            return True
            
        except Exception as e:
            self.log(f"Key management test failed: {e}", "ERROR")
            return False
    
    def test_key_exchange(self) -> bool:
        """Test key exchange functionality."""
        try:
            # Initiate key exchange
            response = requests.post(f"{self.base_url}/api/keys/exchange", 
                                   json={
                                       "initiator_id": self.alice,
                                       "recipient_id": self.bob
                                   }, timeout=5)
            assert response.status_code == 201, f"Key exchange failed: {response.status_code}"
            exchange_data = response.json()
            
            assert "session_id" in exchange_data, "Session ID missing"
            assert "encrypted_key_for_initiator" in exchange_data, "Encrypted key for initiator missing"
            assert "encrypted_key_for_recipient" in exchange_data, "Encrypted key for recipient missing"
            assert "initiator_signature" in exchange_data, "Initiator signature missing"
            assert "expires_at" in exchange_data, "Session expiration missing"
            
            self.session_id = exchange_data["session_id"]
            
            # Test get session info
            response = requests.get(f"{self.base_url}/api/keys/session/{self.session_id}?user_id={self.alice}", timeout=5)
            assert response.status_code == 200, f"Get session info failed: {response.status_code}"
            session_data = response.json()
            assert session_data["session_id"] == self.session_id, "Session ID mismatch"
            assert session_data["user1_id"] == self.alice, "Session initiator mismatch"
            assert session_data["user2_id"] == self.bob, "Session recipient mismatch"
            
            # Test get user sessions
            response = requests.get(f"{self.base_url}/api/keys/sessions/{self.alice}", timeout=5)
            assert response.status_code == 200, f"Get user sessions failed: {response.status_code}"
            sessions_data = response.json()
            assert sessions_data["user_id"] == self.alice, "User ID mismatch"
            assert len(sessions_data["sessions"]) > 0, "No sessions found"
            
            return True
            
        except Exception as e:
            self.log(f"Key exchange test failed: {e}", "ERROR")
            return False
    
    def test_attack_lab_status(self) -> bool:
        """Test Attack Lab API status."""
        try:
            response = requests.get(f"{self.base_url}/api/attack-lab/status", timeout=5)
            assert response.status_code == 200, f"Attack lab status failed: {response.status_code}"
            status_data = response.json()
            assert status_data["status"] == "ready", "Attack lab not ready"
            assert "attacks" in status_data, "Attack list missing"
            assert len(status_data["attacks"]) >= 4, "Not enough attacks available"
            
            required_attacks = ["replay", "tampering", "mitm", "dos"]
            for attack in required_attacks:
                assert attack in status_data["attacks"], f"Attack {attack} missing"
            
            return True
            
        except Exception as e:
            self.log(f"Attack lab status test failed: {e}", "ERROR")
            return False
    
    def test_attack_lab_replay(self) -> bool:
        """Test Replay Attack demonstration."""
        try:
            # Test vulnerable mode
            response = requests.post(f"{self.base_url}/api/attack-lab/replay", 
                                   json={"with_defense": False}, timeout=10)
            assert response.status_code == 200, f"Replay attack (vulnerable) failed: {response.status_code}"
            vulnerable_data = response.json()
            assert "attack_type" in vulnerable_data, "Attack type missing"
            assert vulnerable_data["attack_type"] == "replay", "Wrong attack type"
            assert "attack_success" in vulnerable_data, "Attack success status missing"
            assert vulnerable_data["attack_success"] == True, "Vulnerable attack should succeed"
            
            # Test defended mode
            response = requests.post(f"{self.base_url}/api/attack-lab/replay", 
                                   json={"with_defense": True}, timeout=10)
            assert response.status_code == 200, f"Replay attack (defended) failed: {response.status_code}"
            defended_data = response.json()
            assert defended_data["attack_type"] == "replay", "Wrong attack type"
            assert "attack_success" in defended_data, "Attack success status missing"
            assert defended_data["attack_success"] == False, "Defended attack should fail"
            
            # Test comparison
            response = requests.get(f"{self.base_url}/api/attack-lab/compare/replay", timeout=10)
            assert response.status_code == 200, f"Replay attack comparison failed: {response.status_code}"
            comparison_data = response.json()
            assert "vulnerable" in comparison_data, "Vulnerable data missing"
            assert "defended" in comparison_data, "Defended data missing"
            assert "comparison" in comparison_data, "Comparison data missing"
            
            return True
            
        except Exception as e:
            self.log(f"Attack lab replay test failed: {e}", "ERROR")
            return False
    
    def test_attack_lab_tampering(self) -> bool:
        """Test Ciphertext Tampering demonstration."""
        try:
            # Test vulnerable mode
            response = requests.post(f"{self.base_url}/api/attack-lab/tampering", 
                                   json={"with_defense": False}, timeout=10)
            assert response.status_code == 200, f"Tampering attack (vulnerable) failed: {response.status_code}"
            vulnerable_data = response.json()
            assert vulnerable_data["attack_type"] == "tampering", "Wrong attack type"
            assert vulnerable_data["attack_success"] == True, "Vulnerable attack should succeed"
            
            # Test defended mode
            response = requests.post(f"{self.base_url}/api/attack-lab/tampering", 
                                   json={"with_defense": True}, timeout=10)
            assert response.status_code == 200, f"Tampering attack (defended) failed: {response.status_code}"
            defended_data = response.json()
            assert defended_data["attack_type"] == "tampering", "Wrong attack type"
            assert defended_data["attack_success"] == False, "Defended attack should fail"
            
            return True
            
        except Exception as e:
            self.log(f"Attack lab tampering test failed: {e}", "ERROR")
            return False
    
    def test_attack_lab_mitm(self) -> bool:
        """Test MITM Attack demonstration."""
        try:
            # Test vulnerable mode
            response = requests.post(f"{self.base_url}/api/attack-lab/mitm", 
                                   json={"with_defense": False}, timeout=10)
            assert response.status_code == 200, f"MITM attack (vulnerable) failed: {response.status_code}"
            vulnerable_data = response.json()
            assert vulnerable_data["attack_type"] == "mitm", "Wrong attack type"
            assert vulnerable_data["attack_success"] == True, "Vulnerable attack should succeed"
            
            # Test defended mode
            response = requests.post(f"{self.base_url}/api/attack-lab/mitm", 
                                   json={"with_defense": True}, timeout=10)
            assert response.status_code == 200, f"MITM attack (defended) failed: {response.status_code}"
            defended_data = response.json()
            assert defended_data["attack_type"] == "mitm", "Wrong attack type"
            assert defended_data["attack_success"] == False, "Defended attack should fail"
            
            return True
            
        except Exception as e:
            self.log(f"Attack lab MITM test failed: {e}", "ERROR")
            return False
    
    def test_attack_lab_dos(self) -> bool:
        """Test DoS Attack demonstration."""
        try:
            # Test vulnerable mode
            response = requests.post(f"{self.base_url}/api/attack-lab/dos", 
                                   json={"with_defense": False}, timeout=10)
            assert response.status_code == 200, f"DoS attack (vulnerable) failed: {response.status_code}"
            vulnerable_data = response.json()
            assert vulnerable_data["attack_type"] == "dos", "Wrong attack type"
            assert vulnerable_data["attack_success"] == True, "Vulnerable attack should succeed"
            
            # Test defended mode
            response = requests.post(f"{self.base_url}/api/attack-lab/dos", 
                                   json={"with_defense": True}, timeout=10)
            assert response.status_code == 200, f"DoS attack (defended) failed: {response.status_code}"
            defended_data = response.json()
            assert defended_data["attack_type"] == "dos", "Wrong attack type"
            assert defended_data["attack_success"] == False, "Defended attack should fail"
            
            return True
            
        except Exception as e:
            self.log(f"Attack lab DoS test failed: {e}", "ERROR")
            return False
    
    def test_attack_lab_run_all(self) -> bool:
        """Test running all attacks at once."""
        try:
            # Test all attacks with defense
            response = requests.post(f"{self.base_url}/api/attack-lab/run-all", 
                                   json={"with_defense": True}, timeout=30)
            assert response.status_code == 200, f"Run all attacks failed: {response.status_code}"
            all_data = response.json()
            assert "results" in all_data, "Results missing"
            assert "summary" in all_data, "Summary missing"
            
            results = all_data["results"]
            assert len(results) == 4, "Not all attack results present"
            
            # All defended attacks should fail
            for attack_type, attack_data in results.items():
                assert attack_data["attack_success"] == False, f"Defended {attack_type} attack should fail"
            
            # Summary should show 0 attacks succeeded
            summary = all_data["summary"]
            assert summary["attacks_succeeded"] == 0, "Defended mode should have 0 successful attacks"
            assert summary["attacks_blocked"] == 4, "Defended mode should block all 4 attacks"
            assert summary["defense_effective"] == True, "Defense should be effective"
            
            return True
            
        except Exception as e:
            self.log(f"Attack lab run all test failed: {e}", "ERROR")
            return False
    
    def test_complete_workflow(self) -> bool:
        """Test complete workflow: register users, exchange keys, verify functionality."""
        try:
            # This test verifies that all components work together
            # We've already tested individual components, so this is a final integration check
            
            # Verify users are registered (from previous tests)
            response = requests.get(f"{self.base_url}/api/users", timeout=5)
            assert response.status_code == 200, "Users endpoint not working"
            users_data = response.json()
            user_ids = [user["user_id"] for user in users_data["users"]]
            assert self.alice in user_ids, f"{self.alice} not found in users"
            assert self.bob in user_ids, f"{self.bob} not found in users"
            
            # Verify session exists (from previous test)
            if self.session_id:
                response = requests.get(f"{self.base_url}/api/keys/session/{self.session_id}?user_id={self.alice}", timeout=5)
                assert response.status_code == 200, "Session verification failed"
            
            # Verify Attack Lab is fully functional
            response = requests.get(f"{self.base_url}/api/attack-lab/status", timeout=5)
            assert response.status_code == 200, "Attack Lab not functional"
            status_data = response.json()
            assert status_data["status"] == "ready", "Attack Lab not ready"
            
            return True
            
        except Exception as e:
            self.log(f"Complete workflow test failed: {e}", "ERROR")
            return False
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all integration tests and return summary."""
        self.log("Starting SecureChat Integration Tests", "INFO")
        self.log("=" * 60, "INFO")
        
        # Define all tests
        tests = [
            ("Cryptography Modules", self.test_cryptography_modules),
            ("API Health Check", self.test_api_health),
            ("User Registration", self.test_user_registration),
            ("Key Management", self.test_key_management),
            ("Key Exchange", self.test_key_exchange),
            ("Attack Lab Status", self.test_attack_lab_status),
            ("Attack Lab - Replay", self.test_attack_lab_replay),
            ("Attack Lab - Tampering", self.test_attack_lab_tampering),
            ("Attack Lab - MITM", self.test_attack_lab_mitm),
            ("Attack Lab - DoS", self.test_attack_lab_dos),
            ("Attack Lab - Run All", self.test_attack_lab_run_all),
            ("Complete Workflow", self.test_complete_workflow),
        ]
        
        # Run each test
        for test_name, test_func in tests:
            self.run_test(test_name, test_func)
            time.sleep(0.1)  # Small delay between tests
        
        # Generate summary
        total_tests = len(tests)
        passed_count = len(self.passed_tests)
        failed_count = len(self.failed_tests)
        success_rate = (passed_count / total_tests) * 100 if total_tests > 0 else 0
        
        summary = {
            "timestamp": datetime.now().isoformat(),
            "total_tests": total_tests,
            "passed": passed_count,
            "failed": failed_count,
            "success_rate": round(success_rate, 2),
            "passed_tests": self.passed_tests,
            "failed_tests": self.failed_tests,
            "detailed_results": self.test_results
        }
        
        # Print summary
        self.log("=" * 60, "INFO")
        self.log(f"INTEGRATION TEST SUMMARY", "INFO")
        self.log("=" * 60, "INFO")
        self.log(f"Total Tests: {total_tests}", "INFO")
        self.log(f"Passed: {passed_count}", "PASS")
        self.log(f"Failed: {failed_count}", "FAIL")
        self.log(f"Success Rate: {success_rate:.2f}%", "INFO")
        self.log("=" * 60, "INFO")
        
        if self.failed_tests:
            self.log("FAILED TESTS:", "FAIL")
            for test in self.failed_tests:
                self.log(f"  - {test}", "FAIL")
            self.log("=" * 60, "INFO")
        
        # Save results to file
        with open("integration_test_results.json", "w") as f:
            json.dump(summary, f, indent=2)
        
        self.log(f"Test results saved to integration_test_results.json", "INFO")
        
        return summary


def main():
    """Main entry point for integration testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description="SecureChat Integration Test Suite")
    parser.add_argument("--host", default="localhost", help="Server host (default: localhost)")
    parser.add_argument("--port", type=int, default=5000, help="Server port (default: 5000)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--skip-attack-lab", action="store_true", help="Skip Attack Lab tests")
    
    args = parser.parse_args()
    
    # Check if server is running
    try:
        response = requests.get(f"http://{args.host}:{args.port}/api/health", timeout=5)
        if response.status_code != 200:
            print(f"Error: Server at {args.host}:{args.port} is not responding correctly")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"Error: Cannot connect to server at {args.host}:{args.port}")
        print("Please ensure the SecureChat server is running before running tests")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"Error: Connection to {args.host}:{args.port} timed out")
        sys.exit(1)
    
    # Run tests
    tester = SecureChatIntegrationTest(args.host, args.port, args.verbose)
    results = tester.run_all_tests()
    
    # Exit with appropriate code
    if results["failed"] > 0:
        sys.exit(1)
    else:
        print("🎉 All integration tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()