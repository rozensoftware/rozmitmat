# rozmitmat

Version: 0.1.0

This is a Rust implementation of an ARP spoof attack and Python implementation of a DNS spoof attack..

Rozmitmat is a vision of a hacking tool I am developing for a knowledge gathering about how network and Linux/Windows systems work.
It is working on Linux only.

## Building

For Rust part:

Install libpcap-dev:

```bash
sudo apt-get install libpcap-dev
```

For Python part:

Install:

```bash
sudo apt-get install build-essential python3-dev libnetfilter-queue-dev
pip3 install NetfilterQueue
pip3 install scapy
```

Note - Python version does an ARP spoof attack also.

## Usage

To prepare attacks based on MITM run rozmitmat:

```bash
sudo ./rozmitmat --interface eth0 --target 192.168.0.22 --gateway 192.168.0.1
```

*interface* is the name of the network interface you want to use as the input device

*target* is the target IP of the computer you want to hack

*gateway* is the router IP

Add *--verbose* for more detailed output.

To do a DNS attack you have to run Python script:

```bash
sudo rozdnsspoof.py -n NETWORK -g GATEWAYIP -t TARGETIP -d DOMAIN -r REDIRECTTOIP
```

Where:

*NETWORK* - A name of your network device

*GATEWAY* - The IP of a router (e.g. 192.168.0.1)

*TARGETIP* - The IP of the target machine

*DOMAIN* - The domain name you'd like to spoof, e.g. bing.com

*REDIRECTTOIP* - The IP where the attack will be redirected to, e.g. your Kali Apache2 server with a prepared page.


## License

This project is licensed under either of

Apache License, Version 2.0, (LICENSE-APACHE or <http://www.apache.org/licenses/LICENSE-2.0>)
MIT license (LICENSE-MIT or <http://opensource.org/licenses/MIT>)
at your option.

## Contributing / Feedback

I am always glad to learn from anyone.
If you want to contribute, you are more than welcome to be a part of the project! Try to share you thoughts first! Feel free to open a new issue if you want to discuss new ideas.

Any kind of feedback is welcome!