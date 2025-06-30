import pyshark
import urllib.parse
import re
import csv
from tqdm import trange
import os


def extract_sni_with_pyshark(pcap_file, ssllog):
    cap = pyshark.FileCapture(pcap_file, display_filter="tls.handshake.extensions_server_name",
                              tshark_path=r'D:\Wireshark\tshark.exe',
                              override_prefs={'ssl.keylog_file': f'{ssllog}'})
    snis = set()
    for pkt in cap:
        try:
            sni = pkt.tls.handshake_extensions_server_name
            snis.add(sni)
        except AttributeError:
            continue
    cap.close()
    return snis


def extract_urls_from_pcap(pcap_file, ssllog):
    cap = pyshark.FileCapture(pcap_file, display_filter="http or http2",
                              tshark_path=r'D:\Wireshark\tshark.exe',
                              override_prefs={'ssl.keylog_file': f'{ssllog}'},
                              )

    url_to_stream = {}
    http_packet_count = 0

    for pkt in cap:
        # 处理 HTTP/1.x
        if hasattr(pkt, 'http') and hasattr(pkt.http, 'host'):
            stream_index = pkt.tcp.stream
            http_packet_count += 1
            url = f"http://{pkt.http.host}"
            if hasattr(pkt.http, 'request_uri'):
                url += pkt.http.request_uri
            normalized_url = normalize_url(url)
            if normalized_url in url_to_stream:
                url_to_stream[normalized_url].add(stream_index)
                # print(url, stream_index)
            else:
                url_to_stream[normalized_url] = {stream_index}

        # 处理 HTTP/2
        elif hasattr(pkt, 'http2'):
            http_packet_count += 1
            try:
                host = getattr(pkt.http2, 'headers_authority', None)
                path = getattr(pkt.http2, 'headers_path', None)
                if host:
                    url = f"https://{host}"
                if path:
                    url += path
                normalized_url = normalize_url(url)
                stream_index = pkt.tcp.stream
                if normalized_url in url_to_stream:
                    url_to_stream[normalized_url].add(stream_index)
                    # print(url, stream_index, str(pcap_file))
                else:
                    url_to_stream[normalized_url] = {stream_index}
            except Exception:
                continue

    cap.close()
    return url_to_stream


def normalize_url(url):
    """
    规范化URL：去除查询参数、协议和端口号、文件名和文件扩展名，以及伪随机字符串。
    """
    # 解析URL
    parsed_url = urllib.parse.urlparse(url)
    # 提取域名
    domain = parsed_url.netloc
    # 提取路径
    path = parsed_url.path
    # 去除路径中的文件名和文件扩展名
    if '.' in path.split('/')[-1]:
        path = '/'.join(path.split('/')[:-1]) + '/'
    else:
        path = path.rstrip('/') + '/'

    # 定义伪随机字符串的正则表达式
    random_string_patterns = [
        re.compile(r'[a-zA-Z0-9]{10,}'),  # 字母和数字混合，长度≥10
        re.compile(r'[0-9]{10,}'),  # 纯数字，长度≥10
        re.compile(r'[0-9.]+'),  # 数字和'.'混合，长度≥10
        re.compile(r'[a-zA-Z0-9_-]{10,}'),  # 字母、数字、'-'、'_'混合，长度≥10
    ]

    # 分割路径，检查并移除伪随机字符串
    path_parts = path.split('/')
    cleaned_parts = []
    for part in path_parts:
        if part:
            # 检查是否匹配任一伪随机字符串模式
            is_random = any(pattern.fullmatch(part) for pattern in random_string_patterns)
            if not is_random:
                cleaned_parts.append(part)
            else:
                break

    # 重新组合路径
    cleaned_path = '/'.join(cleaned_parts) + '/' if cleaned_parts else ''

    # 组合域名和路径
    normalized_url = domain + '/' + cleaned_path
    return normalized_url


def merge_dict(dict1, dict2):
    """
    合并两个字典，将相同的URL的流索引合并。
    """
    merged_dict = dict1.copy()
    for url, streams in dict2.items():
        if url in merged_dict:
            merged_dict[url].update(streams)
        else:
            merged_dict[url] = streams
    return merged_dict


def find_ad_urls(ad_pcap, no_ad_pcap, ssllog):
    """
    比较包含广告流量的URL和不包含广告流量的URL，计算差集以识别广告相关的URL。
    """
    ad_url_stream = extract_urls_from_pcap(ad_pcap, ssllog)
    no_ad_url_stream = extract_urls_from_pcap(no_ad_pcap, ssllog)

    # 使用关键字过滤广告URL
    pattern = r'(adserver|doubleclick|clickid|adid|utm_source|utm_campaign)'
    ad_pattern = re.compile(pattern)
    filtered_ad_url_stream = {
        url: stream_indices for url, stream_indices in ad_url_stream.items()
        if ad_pattern.search(url)
    }

    ad_only_urls = {url: streams for url, streams in ad_url_stream.items() if url not in no_ad_url_stream}

    ad_url_stream = merge_dict(ad_only_urls, filtered_ad_url_stream)

    return ad_url_stream


if __name__ == "__main__":
    result_path = r'./result_chrome_3'
    ssllog = os.path.join(result_path, 'ssllog.txt')
    ad_stream_dir = os.path.join(result_path, 'ad_stream')
    if not os.path.exists(ad_stream_dir):
        os.makedirs(ad_stream_dir)

    # 读取top500 url列表
    with open('./chinaz_url_500.txt', 'r') as csvfile:
        reader = csv.reader(csvfile)
        data = [row[0] for row in reader]

    for i in trange(len(data)):
        fname = data[i]
        ad_pcap_path = f"{result_path}/pcap/{fname.replace('.', '_')}_Ad.pcap"
        noAd_pcap_path = f"{result_path}/pcap/{fname.replace('.', '_')}_noAd.pcap"

        if not (os.path.exists(ad_pcap_path) and os.path.exists(noAd_pcap_path)):
            print(f"Missing pcap files for {fname}")
            continue

        ad_url_stream = find_ad_urls(ad_pcap_path, noAd_pcap_path, ssllog)
        ad_stream = set()
        for url, streams in ad_url_stream.items():
            ad_stream.update(streams)

        # 保存 stream ad_url_stream
        with open(f"{result_path}/ad_stream/{fname.replace('.', '_')}_ad_urls.csv", 'w') as f:
            wirter = csv.writer(f)
            for ad_url, streams in ad_url_stream.items():
                wirter.writerow([ad_url, ','.join(map(str, streams))])

        # 保存stream id
        with open(f"{result_path}/ad_stream/{fname.replace('.', '_')}_ad_streams.txt", 'w') as f:
            for stream in ad_stream:
                f.write(f"{stream}\t")
