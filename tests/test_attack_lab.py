"""
Attack Lab Tests

Tests for the Attack Lab demonstrations:
- Replay attack demo (with/without defense)
- Tampering attack demo (with/without defense)
- MITM attack demo (with/without defense)
- DoS attack demo (with/without defense)
- API endpoints
"""

import pytest

from attack_lab.replay import demo as replay_demo
from attack_lab.tampering import demo as tampering_demo
from attack_lab.mitm import demo as mitm_demo
from attack_lab.dos import demo as dos_demo


class TestReplayAttackDemo:
    """Tests for replay attack demonstration."""

    def test_replay_attack_without_defense_succeeds(self):
        """Test that replay attack succeeds without defense."""
        result = replay_demo.run_demo(with_defense=False)
        
        assert result['attack_type'] == 'replay'
        assert result['with_defense'] is False
        assert result['attack_success'] is True
        assert result['defense_status'] == 'disabled'

    def test_replay_attack_with_defense_fails(self):
        """Test that replay attack fails with defense enabled."""
        result = replay_demo.run_demo(with_defense=True)
        
        assert result['attack_type'] == 'replay'
        assert result['with_defense'] is True
        assert result['attack_success'] is False
        assert result['defense_status'] == 'enabled'

    def test_replay_attack_returns_steps(self):
        """Test that demo returns execution steps."""
        result = replay_demo.run_demo(with_defense=False)
        
        assert 'steps' in result
        assert len(result['steps']) > 0
        assert all('step' in s and 'action' in s for s in result['steps'])

    def test_replay_attack_returns_logs(self):
        """Test that demo returns event logs."""
        result = replay_demo.run_demo(with_defense=False)
        
        assert 'logs' in result
        assert len(result['logs']) > 0
        assert all('level' in log and 'message' in log for log in result['logs'])

    def test_replay_attack_returns_summary(self):
        """Test that demo returns summary."""
        result = replay_demo.run_demo(with_defense=False)
        
        assert 'summary' in result
        assert len(result['summary']) > 0


class TestTamperingAttackDemo:
    """Tests for ciphertext tampering attack demonstration."""

    def test_tampering_attack_without_defense_succeeds(self):
        """Test that tampering attack succeeds without defense."""
        result = tampering_demo.run_demo(with_defense=False)
        
        assert result['attack_type'] == 'tampering'
        assert result['with_defense'] is False
        assert result['attack_success'] is True

    def test_tampering_attack_with_defense_fails(self):
        """Test that tampering attack fails with GCM authentication."""
        result = tampering_demo.run_demo(with_defense=True)
        
        assert result['attack_type'] == 'tampering'
        assert result['with_defense'] is True
        assert result['attack_success'] is False

    def test_tampering_attack_returns_steps(self):
        """Test that demo returns execution steps."""
        result = tampering_demo.run_demo(with_defense=True)
        
        assert 'steps' in result
        assert len(result['steps']) > 0

    def test_tampering_attack_returns_summary(self):
        """Test that demo returns summary."""
        result = tampering_demo.run_demo(with_defense=True)
        
        assert 'summary' in result


class TestMITMAttackDemo:
    """Tests for Man-in-the-Middle attack demonstration."""

    def test_mitm_attack_without_defense_succeeds(self):
        """Test that MITM attack succeeds without signature verification."""
        result = mitm_demo.run_demo(with_defense=False)
        
        assert result['attack_type'] == 'mitm'
        assert result['with_defense'] is False
        assert result['attack_success'] is True

    def test_mitm_attack_with_defense_fails(self):
        """Test that MITM attack fails with signature verification."""
        result = mitm_demo.run_demo(with_defense=True)
        
        assert result['attack_type'] == 'mitm'
        assert result['with_defense'] is True
        assert result['attack_success'] is False

    def test_mitm_attack_returns_steps(self):
        """Test that demo returns execution steps."""
        result = mitm_demo.run_demo(with_defense=False)
        
        assert 'steps' in result
        assert len(result['steps']) > 0

    def test_mitm_attack_returns_summary(self):
        """Test that demo returns summary."""
        result = mitm_demo.run_demo(with_defense=False)
        
        assert 'summary' in result


class TestDoSAttackDemo:
    """Tests for Denial of Service attack demonstration."""

    def test_dos_attack_without_defense_succeeds(self):
        """Test that DoS attack succeeds without rate limiting."""
        result = dos_demo.run_demo(with_defense=False)
        
        assert result['attack_type'] == 'dos'
        assert result['with_defense'] is False
        assert result['attack_success'] is True

    def test_dos_attack_with_defense_fails(self):
        """Test that DoS attack is mitigated with rate limiting."""
        result = dos_demo.run_demo(with_defense=True)
        
        assert result['attack_type'] == 'dos'
        assert result['with_defense'] is True
        assert result['attack_success'] is False

    def test_dos_attack_returns_steps(self):
        """Test that demo returns execution steps."""
        result = dos_demo.run_demo(with_defense=True)
        
        assert 'steps' in result
        assert len(result['steps']) > 0

    def test_dos_attack_returns_metrics(self):
        """Test that DoS demo returns attack metrics."""
        result = dos_demo.run_demo(with_defense=False)
        
        assert 'summary' in result


class TestAttackLabAPI:
    """Tests for Attack Lab API endpoints."""

    def test_get_status(self, client):
        """Test GET /api/attack-lab/status returns available attacks."""
        response = client.get('/api/attack-lab/status')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'ready'
        assert 'attacks' in data
        assert 'replay' in data['attacks']
        assert 'tampering' in data['attacks']
        assert 'mitm' in data['attacks']
        assert 'dos' in data['attacks']

    def test_run_replay_attack_endpoint(self, client):
        """Test POST /api/attack-lab/replay runs replay attack demo."""
        response = client.post(
            '/api/attack-lab/replay',
            json={'with_defense': False},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['attack_type'] == 'replay'

    def test_run_tampering_attack_endpoint(self, client):
        """Test POST /api/attack-lab/tampering runs tampering attack demo."""
        response = client.post(
            '/api/attack-lab/tampering',
            json={'with_defense': False},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['attack_type'] == 'tampering'

    def test_run_mitm_attack_endpoint(self, client):
        """Test POST /api/attack-lab/mitm runs MITM attack demo."""
        response = client.post(
            '/api/attack-lab/mitm',
            json={'with_defense': False},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['attack_type'] == 'mitm'

    def test_run_dos_attack_endpoint(self, client):
        """Test POST /api/attack-lab/dos runs DoS attack demo."""
        response = client.post(
            '/api/attack-lab/dos',
            json={'with_defense': False},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['attack_type'] == 'dos'

    def test_run_attack_with_defense(self, client):
        """Test running attack with defense enabled."""
        response = client.post(
            '/api/attack-lab/replay',
            json={'with_defense': True},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['with_defense'] is True

    def test_run_all_attacks_endpoint(self, client):
        """Test POST /api/attack-lab/run-all runs all attacks."""
        response = client.post(
            '/api/attack-lab/run-all',
            json={'with_defense': False},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'results' in data
        assert 'replay' in data['results']
        assert 'tampering' in data['results']
        assert 'mitm' in data['results']
        assert 'dos' in data['results']
        assert 'summary' in data

    def test_compare_attack_endpoint(self, client):
        """Test GET /api/attack-lab/compare/<attack_type> compares results."""
        response = client.get('/api/attack-lab/compare/replay')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['attack_type'] == 'replay'
        assert 'vulnerable' in data
        assert 'defended' in data
        assert 'comparison' in data

    def test_compare_invalid_attack_type(self, client):
        """Test comparing invalid attack type returns 400."""
        response = client.get('/api/attack-lab/compare/invalid')
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'valid_types' in data

    def test_attack_default_no_defense(self, client):
        """Test that attacks default to no defense when not specified."""
        response = client.post(
            '/api/attack-lab/replay',
            json={},  # No with_defense specified
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['with_defense'] is False


class TestAttackDefenseComparison:
    """Tests comparing attack behavior with and without defense."""

    def test_replay_defense_effectiveness(self):
        """Test replay defense is effective."""
        without = replay_demo.run_demo(with_defense=False)
        with_defense = replay_demo.run_demo(with_defense=True)
        
        assert without['attack_success'] is True
        assert with_defense['attack_success'] is False

    def test_tampering_defense_effectiveness(self):
        """Test tampering defense (GCM) is effective."""
        without = tampering_demo.run_demo(with_defense=False)
        with_defense = tampering_demo.run_demo(with_defense=True)
        
        assert without['attack_success'] is True
        assert with_defense['attack_success'] is False

    def test_mitm_defense_effectiveness(self):
        """Test MITM defense (signatures) is effective."""
        without = mitm_demo.run_demo(with_defense=False)
        with_defense = mitm_demo.run_demo(with_defense=True)
        
        assert without['attack_success'] is True
        assert with_defense['attack_success'] is False

    def test_dos_defense_effectiveness(self):
        """Test DoS defense (rate limiting) is effective."""
        without = dos_demo.run_demo(with_defense=False)
        with_defense = dos_demo.run_demo(with_defense=True)
        
        assert without['attack_success'] is True
        assert with_defense['attack_success'] is False