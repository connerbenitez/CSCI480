import time
import os
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def capture_screenshots():
    # Setup Chrome options
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in headless mode
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--disable-gpu")
    
    # Initialize driver
    driver = webdriver.Chrome(options=chrome_options)
    
    # Create screenshots directory
    screenshots_dir = r"c:\Users\pompk\Desktop\CSCI480\Demo_Instructions\screenshots"
    os.makedirs(screenshots_dir, exist_ok=True)
    
    base_url = "http://127.0.0.1:5000"
    
    try:
        print("Capturing screenshots...")
        
        # Screenshot 1: Dashboard Overview
        print("1. Capturing dashboard overview...")
        driver.get(base_url)
        time.sleep(3)  # Wait for page to load
        driver.save_screenshot(os.path.join(screenshots_dir, "screenshot_01_dashboard.png"))
        
        # Screenshot 2: Try to access UI if available
        print("2. Capturing UI view...")
        driver.get(f"{base_url}/ui")
        time.sleep(3)
        driver.save_screenshot(os.path.join(screenshots_dir, "screenshot_02_ui.png"))
        
        # Screenshot 3: Results page
        print("3. Capturing results view...")
        driver.get(f"{base_url}/results")
        time.sleep(2)
        driver.save_screenshot(os.path.join(screenshots_dir, "screenshot_03_results.png"))
        
        # Screenshot 4: Defense/Prevention page
        print("4. Capturing defense view...")
        driver.get(f"{base_url}/defense")
        time.sleep(2)
        driver.save_screenshot(os.path.join(screenshots_dir, "screenshot_04_defense.png"))
        
        # Screenshot 5: PCAP Replay page
        print("5. Capturing PCAP replay view...")
        driver.get(f"{base_url}/pcap")
        time.sleep(2)
        driver.save_screenshot(os.path.join(screenshots_dir, "screenshot_05_pcap.png"))
        
        # Screenshot 6: Model settings page
        print("6. Capturing model settings view...")
        driver.get(f"{base_url}/model-settings")
        time.sleep(2)
        driver.save_screenshot(os.path.join(screenshots_dir, "screenshot_06_models.png"))
        
        print(f"\nScreenshots saved to: {screenshots_dir}")
        print("Captured screenshots:")
        for f in os.listdir(screenshots_dir):
            if f.endswith('.png'):
                print(f"  - {f}")
                
    except Exception as e:
        print(f"Error capturing screenshots: {e}")
    finally:
        driver.quit()

if __name__ == "__main__":
    capture_screenshots()
