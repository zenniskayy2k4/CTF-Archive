import threading
from playwright.sync_api import sync_playwright

def admin_bot_visit_url(url, admin_pass):
    """Admin bot visits a URL with admin session using Playwright"""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()

            page = context.new_page()

            page.goto("http://localhost:5000/login")
            page.fill('input[name="username"]', 'admin')
            page.fill('input[name="password"]', admin_pass)
            page.click('button[type="submit"]')

            # Check cake page for issues.
            page.goto(url)
            print(f"📄 Loaded cake page: {url}", flush=True)

            page.wait_for_timeout(3000)

            print("✅ Admin bot done", flush=True)
            browser.close()

    except Exception as e:
        print(f"❌ Admin bot error: {e}", flush=True)

def start_admin_bot(url, admin_pass):
    """Start admin bot in a background thread"""
    print(f"Starting admin bot for URL: {url} with admin password: {admin_pass}", flush=True)
    threading.Thread(target=admin_bot_visit_url, args=(url, admin_pass), daemon=True).start()
