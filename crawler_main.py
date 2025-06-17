import os
import csv
from tqdm import trange
import psutil
import subprocess
import argparse
import logging

import collect_single_pcap_log_sc

logging.basicConfig(
    filename='./crawler.log',  # 日志文件位置
    level=logging.INFO,  # 记录所有级别的日志（INFO及以上）
    format='%(asctime)s - %(levelname)s - %(message)s',  # 日志格式
)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)  # 设置日志级别
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(console_handler)


def init_file_folder(times, browser):
    father = f'./result_{browser}_{times}'
    file_folder = [father, father + '/browser_log', father + '/pcap', father + '/screenshot']
    for folder in file_folder:
        if not os.path.exists(folder):
            os.mkdir(folder)


def generate_pcap_log_sc(father, browser, domain_list_file):
    with open(domain_list_file, 'r') as csvfile:
        reader = csv.reader(csvfile)
        data = [row[0] for row in reader]

    for i in trange(len(data)):
        try:
            collect_single_pcap_log_sc.main_process(f'http://{data[i]}', father, browser, with_adblock=True)
            post_process(father, data[i], browser, with_adblock=True)
        except Exception as e:
            logging.info('main error:', data[i], e)
        finally:
            logging.info(f'-----------complete NoAd {i}/{len(data)}-----------')

        try:
            collect_single_pcap_log_sc.main_process(f'http://{data[i]}', father, browser, with_adblock=False)
            post_process(father, data[i], browser, with_adblock=False)
        except Exception as e:
            logging.info('main error:', data[i], e)
        finally:
            logging.info(f'-----------complete Ad {i}/{len(data)}-----------')


def post_process(father, url, browser, with_adblock):
    ad_suffix = "_noAd" if with_adblock else "_Ad"
    # Handling still open chrome and tcpdump processes
    try:
        subprocess.run(['taskkill', '/F', '/IM', 'tshark.exe'], check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        logging.info("taskkill 运行失败，tshark已退出")
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc_name = browser.split('_')[0] if browser != 'firefox' else 'firefox-bin'
            if proc.name() == proc_name or proc.name() == 'tshark':
                proc.terminate()
        except psutil.NoSuchProcess:
            pass
        except Exception as e:
            logging.info(f'terminate browser or tshark failed{e}')
    # Handling oversize pcap file
    pcap_file = father + '/pcap/' + url.replace('.', '_') + f'{ad_suffix}.pcap'
    log_file = father + '/browser_log/' + url.replace('.', '_') + f'{ad_suffix}.csv'
    max_file_size_bytes = 200 * 1024 * 1024
    min_file_size_bytes = 10 * 1024
    if os.path.exists(pcap_file):
        if os.path.getsize(pcap_file) > max_file_size_bytes:
            os.remove(pcap_file)
            os.path.exists(log_file) and os.remove(log_file)
            logging.info(f'{url}pcap/log/sc deleted - oversize 200mb')
        if os.path.getsize(pcap_file) < min_file_size_bytes:
            os.remove(pcap_file)
            os.path.exists(log_file) and os.remove(log_file)
            logging.info(f'{url}pcap/log/sc deleted - less than 10k')
            with open('./failed_url.txt', 'a+') as failed_url:
                failed_url.write(url + '\t' + str(with_adblock) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='This script processes parameters with domain_list, collection times, browser type and network condition.')
    parser.add_argument('--domain', type=str, default='./chinaz_url_500.txt',
                        help='csv file with domain list')
    parser.add_argument('--times', type=int, default=1, help='determine data collection times')
    parser.add_argument('--browser', type=str, default='chrome', choices=['chrome', 'chrome_legacy', 'firefox'],
                        help='browser type')

    args = parser.parse_args()

    domain_list_file = args.domain
    times = args.times
    browser_type = args.browser

    for i in range(times):
        father = f'./result_{browser_type}_{i + 2}'
        init_file_folder(i + 2, browser_type)
        generate_pcap_log_sc(father, browser_type, domain_list_file)
