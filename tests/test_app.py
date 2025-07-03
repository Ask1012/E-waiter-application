import unittest
from flask import Flask
from wsgi import app  # Replace with your actual app file name

class TestEWaiterApp(unittest.TestCase):

    def setUp(self):
        # Create a test client
        self.app = app.test_client()
        self.app.testing = True

    def test_homepage(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome', response.data)
        
  # Check page content

    def test_login(self):
        response = self.app.post('/owner_login', data={
            'email': 'askk@gmail.com',
            'password': '/Ask1012/'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Dashboard', response.data)  # Adjust to actual page content


if __name__ == '__main__':
    unittest.main()
