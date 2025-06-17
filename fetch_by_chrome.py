import time
import psutil
import csv
from func_timeout import func_set_timeout
import func_timeout
import yaml
import subprocess
import os
import logging

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException
from selenium.common.exceptions import WebDriverException

from selenium.webdriver.common.desired_capabilities import DesiredCapabilities


# logging.basicConfig(
#     filename='./crawler.log',  # 日志文件位置
#     level=logging.INFO,  # 记录所有级别的日志（INFO及以上）
#     format='%(asctime)s - %(levelname)s - %(message)s',  # 日志格式
# )
#
# console_handler = logging.StreamHandler()
# console_handler.setLevel(logging.INFO)  # 设置日志级别
# console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
# logging.getLogger().addHandler(console_handler)

# 访问网页
@func_set_timeout(100)
def process(url: str, father, driver, with_adblock, max_retries=2):
    flag = 1
    browser_log = dict()
    ad_suffix = "_noAd" if with_adblock else "_Ad"

    try:
        driver.set_page_load_timeout(30)
        driver.implicitly_wait(10)
        driver.get(url)

        # Define blocked titles and keywords to check for access restrictions
        blocked_titles = [
            "Attention Required!", "Cloudflare", "Verification Required",
            "Access denied", "Just a moment", "HTTP Status 404",
            "403 Forbidden", "404 Not Found", "Error 404 (Not Found)"
        ]

        blocked_keywords = [
            'restricted area', 'Error 404 (Not Found)', '"status":404',
            'Page Not Found', 'not be found', 'net::ERR_CERT_COMMON_NAME_INVALID',
            'discuss automated access'
        ]

        if any(title in driver.title for title in blocked_titles):
            flag = 0
        if any(keyword in driver.page_source for keyword in blocked_keywords):
            flag = 0
        if 'adobe' in url:
            flag = 0

        time.sleep(3)
        browser_log = driver.get_log('performance')


    except TimeoutException as e:
        error = str(e).split('(Session info')[0]
        logging.info(f'{url}resource loading 30s timeout{error}')
        if float(error.split(': ')[-1].split('\n')[0]) < 2:
            flag = 0
        driver.execute_script("window.stop();")
        browser_log = driver.get_log('performance')

    except WebDriverException as e:
        error = str(e).split('(Session info')[0]
        logging.info(f'{url}webdriver error{error}')
        flag = 0

    except Exception as e:
        logging.info(f'{url}other errors:{str(e)}')
        flag = 0

    finally:
        if flag:
            screenshot_path = father + "/screenshot/" + url.replace('.', '_').split('//')[
                1] + f'{ad_suffix}_screenshot.png'
            driver.get_screenshot_as_file(screenshot_path)
            logging.info(f'{url}screenshot generated successful')

    # saving browser log while there are no exceptions
    if flag:
        with open(father + '/browser_log/' + url.replace('.', '_').split('//')[1] + f'{ad_suffix}.csv', 'w', newline='',
                  encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            for i in range(len(browser_log)):
                writer.writerow(browser_log[i].values())
        logging.info(f'{url}browser_log generated successful')

    return flag


def collect_by_url(url: str, father, browser_loc, driver_loc, with_adblock):
    caps = DesiredCapabilities.CHROME
    caps['goog:loggingPrefs'] = {'performance': 'ALL'}

    chrome_options = webdriver.ChromeOptions()

    # chrome v126
    chrome_options.binary_location = browser_loc
    # chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-cache")
    chrome_options.add_argument("--disable-application-cache")
    chrome_options.add_argument("--disable-component-update")
    chrome_options.add_argument("--no-default-browser-check")
    chrome_options.add_argument("--no-first-run")
    chrome_options.add_argument("--disk-cache-size=0")
    chrome_options.add_argument("--disable-gpu")  # 禁用 GPU 加速
    chrome_options.add_argument("--disable-webgl")  # 显式禁用 WebGL
    chrome_options.add_argument("--use-angle=swiftshader") # 使用cpu渲染图像
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument(
        "user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
    if with_adblock:
        chrome_options.add_extension(r'./chrome/adblock.crx')

    service = Service(driver_loc)
    driver = webdriver.Chrome(options=chrome_options, service=service)

    # Handle Adblock welcome page if enabled
    if with_adblock:
        time.sleep(5)
        handles = driver.window_handles
        if len(handles) > 1:
            driver.switch_to.window(handles[1])
            driver.close()
            driver.switch_to.window(handles[0])
            logging.info(f'{url} Adblock welcome page closed successfully')
        else:
            logging.info(f'{url} No Adblock welcome page detected')
        time.sleep(1)

    # Start tshark for packet capture
    with open('./config.yaml', 'r') as configfile:
        config = yaml.safe_load(configfile)
    interface = config['Data_Collection']['network_interface']
    ad_suffix = "_noAd" if with_adblock else "_Ad"
    pcap_file = father + '/pcap/' + url.split('//')[1].replace('.', '_') + f'{ad_suffix}.pcap'
    tshark_cmd = [
        "tshark",
        "-i", interface,
        "-f", "tcp port 80 or tcp port 443 or udp port 443",
        "-w", pcap_file
    ]
    tshark_process = subprocess.Popen(tshark_cmd)
    logging.info(f'{url} tshark started for packet capture')
    time.sleep(1)

    flag = -1
    try:
        flag = process(url, father, driver, with_adblock)
    except func_timeout.exceptions.FunctionTimedOut:
        logging.info(f'{url} 100s timeout! Attention!')
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.name() == 'chrome':
                    proc.terminate()  # or proc.kill()
                    logging.info('terminate chrome success')
            except psutil.NoSuchProcess:
                pass
            except Exception as e:
                logging.info(f'terminate chrome failed {str(e)}')
    except Exception as e:
        logging.info(f'{url} chrome other error: {str(e)}')
        try:
            if driver.current_url:
                driver.execute_script("window.stop();")
            else:
                logging.info("ChromeDriver session invalidated, skipping operation")
        except Exception as e:
            logging.info("ChromeDriver 会话已失效，跳过操作")
    finally:
        driver.quit()

        if tshark_process:
            tshark_process.terminate()
            tshark_process.wait(2)
            if tshark_process.returncode is None:
                tshark_process.kill()
            logging.info(f'{url} pcap generated successful')
            if flag == -1 and pcap_file and os.path.exists(pcap_file):
                os.remove(pcap_file)
                logging.info(f'{url} pcap deleted - flag is -1')

    return flag


if __name__ == '__main__':
    father = './result'
    with open('./config.yaml', 'r') as configfile:
        config = yaml.safe_load(configfile)
    chrome_loc = config['Data_Collection']['chrome']
    driver_loc = config['Data_Collection']['chrome_driver']
    print(collect_by_url('https://baidu.com', father, chrome_loc, driver_loc, with_adblock=False))
    print(collect_by_url('https://csdn.net', father, chrome_loc, driver_loc, with_adblock=True))
