import tempfile
import unittest
from pathlib import Path
import app as scamshield

class ScamShieldTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        scamshield.DB_PATH = Path(self.tmp.name) / "test.db"
        scamshield.UPLOAD_DIR = Path(self.tmp.name) / "uploads"
        scamshield.UPLOAD_DIR.mkdir()
        scamshield.init_db()
        self.client = scamshield.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_health(self):
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)

    def test_scan_persists(self):
        response = self.client.post('/api/scan', json={'message':'Urgent! Verify your account and send OTP'})
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertGreaterEqual(result['score'], 40)
        self.assertIn('explanations', result)
        history = self.client.get('/api/history').get_json()['items']
        self.assertEqual(len(history), 1)

    def test_empty_scan_rejected(self):
        self.assertEqual(self.client.post('/api/scan', json={}).status_code, 400)


    def test_scamsathi_crypto_rule_is_integrated(self):
        response = self.client.post('/api/scan', json={'message':'Share your wallet seed to claim your reward'})
        self.assertEqual(response.status_code, 200)
        labels = ' '.join(response.get_json()['indicators']).lower()
        self.assertTrue('wallet' in labels or 'reward' in labels)

    def test_incident_create_and_timeline(self):
        created = self.client.post('/api/incidents', json={
            'title':'Suspicious bank SMS', 'incident_type':'Suspicious message',
            'description':'Urgent: verify your account and pay processing fee'
        })
        self.assertEqual(created.status_code, 201)
        incident_id = created.get_json()['id']
        detail = self.client.get(f'/api/incidents/{incident_id}')
        self.assertEqual(detail.status_code, 200)
        event = self.client.post(f'/api/incidents/{incident_id}/events', json={'event_text':'Called official bank number','severity':'low'})
        self.assertEqual(event.status_code, 201)

    def test_registration_validation(self):
        response = self.client.post('/api/auth/register', json={'name':'Test User','email':'test@example.com','password':'short'})
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()


def test_forensics_ioc_extract(client):
    response = client.post('/api/forensics/ioc-extract', json={'text': 'Visit https://example.com/login or email help@example.org IP 8.8.8.8'})
    assert response.status_code == 200
    data = response.get_json()
    assert 'https://example.com/login' in data['indicators']['URLs']
    assert 'help@example.org' in data['indicators']['Email addresses']
    assert '8.8.8.8' in data['indicators']['IPv4 addresses']

def test_forensics_text_fingerprint(client):
    response = client.post('/api/forensics/text-fingerprint', json={'text': 'abc'})
    assert response.status_code == 200
    assert response.get_json()['sha256'] == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

class ScamLureRegressionTests(unittest.TestCase):
    def test_short_reward_link_message_is_not_zero_risk(self):
        result = scamshield.analyse(message='click link to get 50k')
        self.assertGreaterEqual(result['score'], 40)
        self.assertIn(result['risk'], {'SUSPICIOUS', 'HIGH RISK'})
        labels = ' '.join(result['indicators']).lower()
        self.assertTrue('reward' in labels or 'money' in labels or 'click' in labels)
        self.assertTrue(result['explanations'])

    def test_no_match_is_not_described_as_verified_safe(self):
        result = scamshield.analyse(message='Hello, see you tomorrow')
        self.assertIn('not a guarantee of safety', ' '.join(x['why'] for x in result['explanations']).lower())
