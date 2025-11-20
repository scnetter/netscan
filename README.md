# netscan.py — Network Scan Tool

Scan subnets to find the first 3 responding hosts (excluding the first usable IP),
then test each for HTTPS, RDP, SMB, and SSH availability.

## Usage

```bash
./netscan2.py -n <CIDR>
./netscan2.py -f <file>
./netscan2.py -h

## Subnets file for -f option

Text file with one subnet per line in the format <x.x.x.x>/<x>
