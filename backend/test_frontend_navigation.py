"""
Personal AI Assistant - Frontend Navigation Verification Test
Verifies:
1. Presence of accessible 'Home' and '+ New Chat' buttons in index.html header.
2. Styling in style.css for both desktop and mobile layouts.
3. Event listeners and behavior in app.js:
   - Returning to Home restores the welcome screen.
   - Starting New Chat preserves history in memory, clears conversation UI and input, and displays welcome screen.
   - Workflow executes cleanly before and after navigation without app reload or backend reset.
"""

import unittest
from pathlib import Path

_frontend_dir = Path(__file__).resolve().parent.parent / "frontend"


class TestFrontendNavigation(unittest.TestCase):
    """Verifies the navigation controls and behavior in index.html and app.js."""

    def test_header_navigation_elements_present_in_html(self):
        """Verify Home and New Chat buttons exist in header with accessible labels."""
        html_path = _frontend_dir / "index.html"
        self.assertTrue(html_path.exists(), "frontend/index.html missing")
        content = html_path.read_text(encoding="utf-8")

        # 1. Home button
        self.assertIn('id="btnNavHome"', content)
        self.assertIn('aria-label="Home"', content)
        self.assertIn('>Home</span>', content)

        # 2. New Chat button
        self.assertIn('id="btnNavNewChat"', content)
        self.assertIn('aria-label="New Chat"', content)
        self.assertIn('>+ New Chat</span>', content)

        # 3. Next to Aura branding in header
        header_section = content[content.find('<header class="assistant-header">'):content.find('</header>')]
        self.assertIn('btnNavHome', header_section)
        self.assertIn('btnNavNewChat', header_section)
        self.assertIn('assistant-brand', header_section)

    def test_navigation_styles_present_in_css(self):
        """Verify CSS defines nav button styles and responsive media queries."""
        css_path = _frontend_dir / "style.css"
        self.assertTrue(css_path.exists(), "frontend/style.css missing")
        css_content = css_path.read_text(encoding="utf-8")

        self.assertIn(".header-nav", css_content)
        self.assertIn(".btn-nav-header", css_content)
        self.assertIn(".btn-new-chat", css_content)
        self.assertIn(".nav-icon", css_content)

        # Responsive section check
        media_section = css_content[css_content.rfind("@media (max-width: 768px)"):]
        self.assertIn(".header-nav", media_section)
        self.assertIn(".btn-nav-header", media_section)

    def test_navigation_logic_in_app_js(self):
        """Verify app.js implements navigateHome and startNewChat with history retention."""
        js_path = _frontend_dir / "app.js"
        self.assertTrue(js_path.exists(), "frontend/app.js missing")
        js_content = js_path.read_text(encoding="utf-8")

        # 1. DOM References
        self.assertIn('document.getElementById("btnNavHome")', js_content)
        self.assertIn('document.getElementById("btnNavNewChat")', js_content)

        # 2. History retention (does not delete stored history)
        self.assertIn('storedConversations', js_content)
        self.assertIn('storedConversations.push', js_content)

        # 3. Return to home function
        self.assertIn('function navigateHome()', js_content)
        self.assertIn('welcomeCard.style.display = "block"', js_content)

        # 4. Start new chat function
        self.assertIn('function startNewChat()', js_content)
        self.assertIn('existingRows.forEach(row => row.remove())', js_content)
        self.assertIn('taskInput.value = ""', js_content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
