## Image name: faucet/dbuilder

FROM debian:buster

RUN apt-get update && \
  apt-get install -y equivs devscripts dpkg-dev quilt curl nano apt-transport-https apt-utils ssl-cert ca-certificates gnupg lsb-release debhelper dh-systemd git && \
  echo "deb https://packagecloud.io/faucetsdn/faucet/$(lsb_release -si | awk '{print tolower($0)}')/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/faucet.list && \
  curl -L https://packagecloud.io/faucetsdn/faucet/gpgkey | apt-key add - && \
  apt-get update && \
  apt-get install -y ruby-dev build-essential patch zlib1g-dev liblzma-dev make libffi-dev && \
  gem update --system && \
  gem install --no-document rake bundler rails json_pure sass compass package_cloud
