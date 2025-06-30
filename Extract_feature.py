from flowcontainer.extractor import extract
import os

result_path = r'./result_chrome_3/labeled_pcap'
ad_dir = os.path.join(result_path, 'ad')
no_ad_dir = os.path.join(result_path, 'no_ad')


def save_payload_lengths(directory, output_file):
    with open(output_file, 'w') as f:
        for pcap_file in os.listdir(directory):
            f.write("1\t2\t;")
            if pcap_file.endswith('.pcap'):
                pcap_path = os.path.join(directory, pcap_file)
                print(f'Extracting features from {pcap_path}...')
                result = extract(pcap_path)
                for key in result:
                    value = result[key]
                    payload_length = value.payload_lengths
                    for i in payload_length:
                        f.write(f'{i}\t')
            f.write('\n')


# Save payload lengths for ad and no_ad directories
save_payload_lengths(ad_dir, './ad_payload_lengths.num')
save_payload_lengths(no_ad_dir, './no_ad_payload_lengths.num')
