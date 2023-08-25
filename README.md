# rozmitmat

Version: 0.1.0

This is a Rust implementation of an ARP and DNS spoof attack.

Rozmitmat is a vision of a hacking tool I am developing for a knowledge gathering about how network and Linux/Windows systems work.
The project consists of two programs: rozmitmat which does an actual work and rozmitmatgui which is a simple GUI app.
For packets manipulation the program uses an external function written in Python with a powerfull package called Scapy. Rozmitmat executes this function which is much simpler than trying doing the same in Rust.

Those apps work on Linux only.

## Building

```bash
sudo apt-get install libpcap-dev build-essential python3-dev libnetfilter-queue-dev scapy
pip3 install scapy
```

## Usage

To execute ARP-DNS MITM attack run rozmitmat as:

```bash
sudo ./rozmitmat --interface eth0 --target 192.168.0.22 --gateway 192.168.0.1 --domain example.com --redirectto 192.168.0.1
```

*interface* is the name of the network interface you want to use as the input device

*target* is the target IP of the computer you want to hack

*gateway* is the router IP

*domain* is the domain you'd like to spoof, e.g.: bing.com

*redirectto* is the IP address where the domain address will be redirected to

Add *--proxy (-p)* to forward HTTP/S communication to a proxy like mitmproxy. Enter a port number which the proxy is listening on.

Add *--verbose (-v)* for more detailed output. Works the best in conjuction with the *-l* option.

Add *--log (-l)* for saving pcap file with the traffic; with *-v* option shows data like: DNS requests, source and destination addresses, HTTP body.

You can write of course also like this:

```bash
sudo ./rozmitmat -i eth0 -t 192.168.0.22 -g 192.168.0.1 -d example.com -r 192.168.0.1
```

If you only want to spoof ARP:

```bash
sudo ./rozmitmat -i eth0 -t 192.168.0.22 -g 192.168.0.1 -v 1 -l 1
```

Create forwarding to a proxy:

```bash
sudo ./rozmitmat -i eth0 -t 192.168.0.22 -g 192.168.0.1 -v 1 -l 1 -p 8080
```

In two cases above a DNS spoof attack will not be executed. Now you're a man in the middle and you can use other tools for more advanced actions.

CTRL-C will stop execution. The program will try to reverse changes: clean iptables and set original ARP data. If you had a previously set iptables all will be wiped out, nat also.

*pcap* file will be created in the working directory if *--log* parameter has been specified. It can be read by Wireshark for a future analysis.


## GUI

![rozmitmatgui](https://github.com/rozensoftware/rozmitmat/blob/master/rozmitmatgui.jpg)

Right click on the Output windows to see a sub-menu.

It uses egui (https://github.com/emilk/egui)

You have to copy rozmitmat to a rozmitmatgui's folder. Remember to run rozmitmatgui as root with *sudo* command or *su*.

## Note

I found that DNS spoofing implemented here not working well. Seems like only DNS requests based on UDP protocol could be spoofed.
I invite you to take a part in this project if you'd like to help.

## License

This project is licensed under either of

Apache License, Version 2.0, (LICENSE-APACHE or <http://www.apache.org/licenses/LICENSE-2.0>)
MIT license (LICENSE-MIT or <http://opensource.org/licenses/MIT>)
at your option.

## Disclaimer

The author of this code is not responsible for the incorrect operation of the presented code and/or for its incorrect use. The code presented in this project is intended to serve only to learn programming. :)

## Contributing / Feedback

I am always glad to learn from anyone.
If you want to contribute, you are more than welcome to be a part of the project! Try to share your thoughts first! Feel free to open a new issue if you want to discuss new ideas.

Any kind of feedback is welcome!

The work is based on the (<https://github.com/gcarq/arp-spoof>) repository.
