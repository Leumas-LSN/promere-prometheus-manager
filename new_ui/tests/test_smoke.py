import unittest
import sys
import os

# Add parent directory to path to import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, NAV_MENU

class SmokeTest(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_nav_endpoints(self):
        """Option 3: Verify all endpoints defined in NAV_MENU do not 500"""
        print("\n[Smoke Test] Checking Navigation Endpoints...")
        
        # We might need to bypass login for some routes or handle redirects.
        # For this simple smoke test, we check that status code is NOT 500.
        # 200, 301, 302, 401, 403 are all "acceptable" in the sense that the server didn't crash.
        
        for item in NAV_MENU:
            if 'endpoint' in item:
                endpoint = item['endpoint']
                # Skip 'safe_url' protected items if they are special actions without simple GET
                if endpoint == 'logout': continue 

                try:
                    # We need to build the URL. Since we are outside request context,
                    # we can push one or use the test client directly if we knew the URL.
                    # But NAV_MENU stores endpoints.
                    
                    with app.test_request_context():
                        from flask import url_for
                        url = url_for(endpoint)
                    
                    response = self.app.get(url, follow_redirects=True)
                    
                    status = response.status_code
                    print(f"  Checking {endpoint} -> {url} : {status}")
                    
                    self.assertNotEqual(status, 500, f"Endpoint {endpoint} returned 500 Internal Server Error!")
                    
                except Exception as e:
                    self.fail(f"Failed to test endpoint {endpoint}: {e}")

if __name__ == '__main__':
    unittest.main()
