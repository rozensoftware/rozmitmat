# rozmitmat

Version: 0.1.0

This is a Rust implementation of an ARP spoof attack.
Currently this is a work in progress; the main functionality of the program is working fine though.

Rozmitmat is a vision of a hacking tool I am developing for a knowledge gathering about how network and Linux/Windows systems work.
It is working on Linux only.

## Building

Install libpcap-dev:

```bash
sudo apt-get install libpcap-dev
```

## Usage

```bash
sudo ./rozmitmat --interface eth0 --target 192.168.0.22 --gateway 192.168.0.1
```
*interface* is the name of the network interface you want to use as the input device
*target* is the target IP of the computer you want to hack
*gateway* is the router IP

## License

This project is licensed under either of

Apache License, Version 2.0, (LICENSE-APACHE or <http://www.apache.org/licenses/LICENSE-2.0>)
MIT license (LICENSE-MIT or <http://opensource.org/licenses/MIT>)
at your option.

## Contributing / Feedback

I am always glad to learn from anyone.
If you want to contribute, you are more than welcome to be a part of the project! Try to share you thoughts first! Feel free to open a new issue if you want to discuss new ideas.

Any kind of feedback is welcome!