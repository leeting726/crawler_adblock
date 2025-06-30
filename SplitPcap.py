import os
import subprocess
import logging

result_path = "./result_chrome_3"

logging.basicConfig(
    filename= result_path + '/split_pcap.log',  # Log file name
    level=logging.INFO,  # Log level
    format='%(asctime)s - %(levelname)s - %(message)s'  # Log format
)


def file_2_pcap(source_file, target_file):
    cmd = "tshark -F pcap -r %s -w %s"
    command = cmd % (source_file, target_file)
    os.system(command)
    return 0


def split_pcap_by_tcp_stream(result_path, pcap_file, pcap_name, steam_index):
    base_dir = os.path.join(result_path, "labeled_pcap")
    ad_dir = os.path.join(base_dir, "ad")
    noad_dir = os.path.join(base_dir, "no_ad")
    os.makedirs(ad_dir, exist_ok=True)
    os.makedirs(noad_dir, exist_ok=True)

    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    cmd = ["tshark", "-r", pcap_file, "-T", "fields", "-e", "tcp.stream", "-Y", "tcp"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        # 获取唯一流索引并找到最大值
        stream_indices_all = set(int(x) for x in result.stdout.splitlines() if x.strip().isdigit())
        stream_len = max(stream_indices_all) if stream_indices_all else -1
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running tshark to get stream indices: {e}")
        return

    for i in range(stream_len+1):
        if str(i) in steam_index:
            output_file = os.path.join(ad_dir, f"{pcap_name}_stream_{i}.pcap")
            cmd = ["tshark", "-r", pcap_file, "-w", output_file, "-Y", f"tcp.stream=={i}"]
            subprocess.run(cmd, check=True, shell=True)
        else:
            output_file = os.path.join(noad_dir, f"{pcap_name}_stream_{i}.pcap")
            cmd = ["tshark", "-r", pcap_file, "-w", output_file, "-Y", f"tcp.stream=={i}"]
            subprocess.run(cmd, check=True, shell=True)
    logging.info(f"已将 {pcap_name} 按 TCP 流拆分完成，流索引范围: 0-{stream_len}")

    # 将pcapng文件转化为pcap格式
    for p, d, f in os.walk(base_dir):
        for file in f:
            print(file)
            target_file = file.replace('.', '_new.')
            file_2_pcap(p + "\\" + file, p + "\\" + target_file)
            if '_new.pcap' not in file:
                os.remove(p + "\\" + file)


if __name__ == '__main__':
    try:
        pcap_path = os.path.join(result_path, 'pcap')
        label_path = os.path.join(result_path, 'ad_stream')

        file_num = 0
        for label_file in os.listdir(label_path):
            if label_file.endswith('.txt'):
                file_num = file_num + 1
        logging.info(f"待处理文件包含: {file_num}")

        i = 0
        for label_file in os.listdir(label_path):
            if label_file.endswith('.txt'):
                i += 1
                logging.info(f"Processing file {i}/{file_num}: {label_file}")
                with open(os.path.join(label_path, label_file), 'r') as f:
                    label = f.readlines()
                    if label:
                        ad_streams = label[0].strip().split('\t')  # 广告流的index
                        pcap_file = os.path.join(pcap_path,
                                                 label_file.replace('_ad_streams.txt', '_Ad.pcap'))  # 广告流对应的pcap文件
                        pcap_name = label_file.replace('_ad_streams.txt', '_Ad.pcap')
                        logging.info(f"Processing file: {pcap_file}")
                        split_pcap_by_tcp_stream(result_path, pcap_file, pcap_name, ad_streams)
        logging.info("Main process completed")
    except Exception as e:
        logging.error(f"Error in main process: {e}")
