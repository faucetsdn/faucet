from netaddr import IPNetwork, IPAddress
src_ip = "23.246.18.234"
netflix_src_list_raw = tuple(open('./Netflix_AS2906', 'r'))
for netflix_src in netflix_src_list_raw:
	
    if IPAddress(src_ip) in IPNetwork(netflix_src):
    	print "haha"