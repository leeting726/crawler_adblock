
with open('./chinaz_url.txt','r') as chinaz_url:
    urls = chinaz_url.readlines()
    with open('./chinaz_url_500.txt','w') as chinaz_url_500:
        for i in range(500):
            chinaz_url_500.write(urls[i])


