
import os
import time
import base64
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from webdriver_manager.chrome import ChromeDriverManager

class WebAgent:
    def __init__(self, headless=False):
        self.driver = None
        self.headless = headless
        self._init_driver()

    def _init_driver(self):
        options = Options()
        if self.headless:
            options.add_argument("--headless=new")
        
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--start-maximized")
        # Masquer l'automatisation pour éviter d'être bloqué
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        
        try:
            self.driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
            # Patch navigator.webdriver pour éviter la détection simple
            self.driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                'source': """
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined
                    })
                """
            })
            print("✅ Web Agent Initialized (Chrome)")
        except Exception as e:
            print(f"❌ Web Agent Init Failed: {e}")

    def go_to(self, url):
        if not self.driver: return False, "Driver not initialized"
        try:
            print(f"🕵️ WebAgent: Navigating to {url}...")
            self.driver.get(url)
            time.sleep(2) # Basic wait for load
            return True, self.driver.title
        except Exception as e:
            return False, str(e)

    def extract_text(self):
        if not self.driver: return ""
        try:
            # Use JS to traverse textual content and append hrefs to links
            # This is much richer for the LLM researcher
            script = """
            function getVisibleText(node) {
                if (node.nodeType === Node.TEXT_NODE) {
                    return node.textContent.trim();
                }
                if (node.nodeType !== Node.ELEMENT_NODE) return "";
                
                // Skip invisible
                const style = window.getComputedStyle(node);
                if (style.display === 'none' || style.visibility === 'hidden') return "";
                
                let text = "";
                
                if (node.tagName === 'A' && node.href) {
                     // Extract recursively but append URL
                     let inner = "";
                     node.childNodes.forEach(child => inner += getVisibleText(child) + " ");
                     inner = inner.trim();
                     if (inner) return `[LINK: ${inner}](${node.href}) `;
                     return ""; 
                }
                
                // Block elements handling for spacing
                const isBlock = ['DIV', 'P', 'H1', 'H2', 'H3', 'LI', 'BR'].includes(node.tagName);
                
                node.childNodes.forEach(child => {
                     text += getVisibleText(child) + " ";
                });
                
                if (isBlock) text += "\\n";
                return text;
            }
            return getVisibleText(document.body);
            """
            # Fallback straightforward approach if JS fails or is too complex:
            # But let's verify if 'body.text' is sufficient. It is NOT for links.
            # Let's try to just extract all links and append them at the end or interleave?
            # Interleaving is better. Let's use a Python approach with BeautifulSoup if possible, or simple selenium traversal.
            # Selenium traversal is slow. Let's use a simplified JS script.
            
            # SIMPLIFIED JS FOR SPEED: Get text, but replace <a>Text</a> with <a>Text (URL)</a> visually in a clone, then getText.
            script_simple = """
            var clone = document.body.cloneNode(true);
            var links = clone.getElementsByTagName('a');
            for (var i = 0; i < links.length; i++) {
                var href = links[i].getAttribute('href');
                if (href && links[i].innerText.trim().length > 0) {
                     links[i].innerText = links[i].innerText + " (" + href + ")";
                }
            }
            return clone.innerText;
            """
            return self.driver.execute_script(script_simple)
            
        except Exception as e:
             print(f"Extract Text Error: {e}")
             # Fallback
             try: return self.driver.find_element(By.TAG_NAME, "body").text
             except: return ""

    def screenshot(self):
        if not self.driver: return None
        try:
            # Retourne le screenshot en base64
            return self.driver.get_screenshot_as_base64()
        except: return None

    def close(self):
        if self.driver:
            self.driver.quit()
            self.driver = None

    # --- ADVANCED ACTIONS ---
    
    def click_element(self, selector, by=By.CSS_SELECTOR):
        try:
            # Wait for clickable
            element = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((by, selector))
            )
            element.click()
            time.sleep(1)
            return True, "Clicked"
        except Exception as e:
            return False, str(e)

    def type_text(self, selector, text, by=By.CSS_SELECTOR):
        try:
            element = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((by, selector))
            )
            element.clear()
            element.send_keys(text)
            return True, f"Typed: {text}"
        except Exception as e:
            return False, str(e)
            
    def press_key(self, key_name):
        try:
            # Map common keys
            key_map = {
                'ENTER': Keys.ENTER,
                'RETURN': Keys.RETURN,
                'TAB': Keys.TAB,
                'SPACE': Keys.SPACE,
                'BACKSPACE': Keys.BACK_SPACE,
                'ESCAPE': Keys.ESCAPE,
                'DOWN': Keys.ARROW_DOWN,
                'UP': Keys.ARROW_UP
            }
            k = key_map.get(key_name.upper())
            if not k: return False, "Unknown Key"
            
            # Send to active element
            webdriver.ActionChains(self.driver).send_keys(k).perform()
            time.sleep(1)
            return True, f"Pressed {key_name}"
        except Exception as e:
            return False, str(e)

    def get_source(self):
         if not self.driver: return ""
         return self.driver.page_source

# Instance globale (Lazy loading à faire dans le server)
