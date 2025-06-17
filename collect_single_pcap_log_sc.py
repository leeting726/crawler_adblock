import os
import subprocess
import time
import csv
from tqdm import trange
import yaml
import fetch_by_chrome
import logging

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

def main_process(URL, father, browser_type, with_adblock):
    with open('./config.yaml', 'r') as configfile:
        config = yaml.safe_load(configfile)

    ad_suffix = "_noAd" if with_adblock else "_Ad"
    pcap_file = father + '/pcap/' + URL.split('//')[1].replace('.', '_') + f'{ad_suffix}.pcap'

    flag = -1

    try:
        if browser_type == 'chrome':
            browser_loc = config['Data_Collection']['chrome']
            driver_loc = config['Data_Collection']['chrome_driver']
            flag = fetch_by_chrome.collect_by_url(URL, father, browser_loc, driver_loc, with_adblock)
        else:
            logging.info(f'submain error - wrong browser type{URL}')
    except Exception as e:
        logging.info(f'submain error {URL} {str(e)}')

    if flag == -1 and os.path.exists(pcap_file):
        os.remove(pcap_file)
        logging.info(f'{URL}pcap deleted - flag is -1')
        with open('./failed_url.txt', 'a+') as failed_url:
            failed_url.write(URL + '\t' +str(with_adblock) +'\n')

    return 0


if __name__ == '__main__':
    url = ''
    father = './result'

    with open('./chinaz_url_10.txt', 'r') as csvfile:
        reader = csv.reader(csvfile)
        data = [row[0] for row in reader]
    # print(data)

    for i in trange(len(data)):
        try:
            main_process('http://' + data[i], father, browser_type='chrome', with_adblock=True)
        except Exception as e:
            pass
        finally:
            try:
                subprocess.run(['taskkill', '/F', '/IM', 'tshark.exe'], check=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
                logging.info("tshark.exe 进程已终止")
            except subprocess.CalledProcessError as e:
                logging.info("taskkill 运行失败，可能 tshark.exe 不存在")
            except FileNotFoundError as e:
                logging.info("taskkill 命令本身未找到，检查系统环境变量")

        try:
            main_process('http://' + data[i], father, browser_type='chrome', with_adblock=False)
        except Exception as e:
            pass
        finally:
            try:
                subprocess.run(['taskkill', '/F', '/IM', 'tshark.exe'], check=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
                logging.info("tshark.exe 进程已终止")
            except subprocess.CalledProcessError as e:
                logging.info("taskkill 运行失败，tshark已结束进程")
            except FileNotFoundError as e:
                logging.info("taskkill 命令本身未找到，检查系统环境变量")
