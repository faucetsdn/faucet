sudo docker build --pull -t c65faucet/tests -f Dockerfile.tests .
sudo docker run --name=faucet-tests \
	        --sysctl net.ipv6.conf.all.disable_ipv6=0 --privileged --cap-add=ALL --rm \
		-v /lib/modules:/lib/modules \
                -v /var/local/lib/docker:/var/lib/docker \
                -v /tmp/faucet-pip-cache:/var/tmp/pip-cache \
		-e FAUCET_TESTS="-un FaucetUntaggedTest" \
                -ti c65faucet/tests
