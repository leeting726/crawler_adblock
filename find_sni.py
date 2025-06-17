import pyshark

def extract_sni_with_pyshark(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="tls.handshake.extensions_server_name")
    snis = set()
    for pkt in cap:
        try:
            sni = pkt.tls.handshake_extensions_server_name
            snis.add(sni)
        except AttributeError:
            continue
    cap.close()
    return snis

def extract_http_and_http2_urls(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="http or http2",
                              override_prefs={'ssl.keylog_file': 'C:/ssllog/ssllog.txt'})
    
    urls = set()
    http_packet_count = 0

    for pkt in cap:
        # 处理 HTTP/1.x
        if hasattr(pkt, 'http') and hasattr(pkt.http, 'host'):
            http_packet_count += 1
            url = f"http://{pkt.http.host}"
            if hasattr(pkt.http, 'request_uri'):
                url += pkt.http.request_uri
            urls.add(url)

        # 处理 HTTP/2
        elif hasattr(pkt, 'http2'):
            http_packet_count += 1
            # http2.headers 是数组形式，需要查找 ':authority' 和 ':path'
            try:
                host = getattr(pkt.http2, 'headers_authority', None)
                path = getattr(pkt.http2, 'headers_path', None)

                if host:
                    url = f"https://{host}"
                if path:
                    url += path
                urls.add(url)
            except Exception:
                # 忽略异常包
                continue

    cap.close()
    return http_packet_count, urls


if __name__ == "__main__":
    pcap_path = r"C:/Users/Public/ad/result_chrome_1/pcap/qq_com_noAd.pcap"
    sni_list = extract_sni_with_pyshark(pcap_path)
    for sni in sni_list:
        print(sni)
    
    http_packet_count, urls = extract_http_and_http2_urls(pcap_path)
    print(f"总共抓取到 {http_packet_count} 个 HTTP 数据包")
    print("访问的 URL:")
    for url in urls:
        print(url)

    
