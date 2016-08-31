# nmurl

nmurl combines nmap output and DNS data to produce HTTP[S] URLs of interest.

# Examples / Usage

Perform an Nmap scan on your desired target:

```
> nmap 10.32.64.0/27 -oX scan.xml

Starting Nmap 6.47 ( http://nmap.org ) at 2016-08-31 02:26 EDT
Nmap scan report for 10.32.64.1
Host is up (0.071s latency).
PORT    STATE  SERVICE
80/tcp  closed http
443/tcp closed https

Nmap scan report for 10.32.64.2
Host is up (0.073s latency).
PORT    STATE    SERVICE
80/tcp  filtered http
443/tcp filtered https

Nmap scan report for www.example.com (10.32.64.4)
Host is up (0.075s latency).
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
```

Get forward lookup data into some file(s) using dig, nmine or anything which
produces DNS data in BIND zone file format:

```
> cat lookups 
host1.example.com.               600 IN A 10.32.64.1
host2.example.com.               600 IN A 10.32.64.2
www.example.com.                 600 IN CNAME host2.example.com
example.com.                     600 IN A 10.32.64.2
host4.example.com.               600 IN A 10.32.64.4
```

Use nmurl to get a list of URLs based on a combination of both data sources:

```
> nmurl scan.xml -n lookups
http://10.32.64.1
http://host1.example.com
https://10.32.64.1
https://host1.example.com
https://10.32.64.2
https://example.com
https://host2.example.com
https://www.example.com
http://10.32.64.4
http://host4.example.com
https://10.32.64.4
https://host4.example.com
```

The URLs above are sorted by IP address and port number.

# Options

* (loose arguments): Filename(s) of Nmap XML output files. Specify at least
once.  No duplicate URLs will be output.

* -n NAMEFILES: Filename of DNS lookup data in BIND zone file
format.  May be specified multiple times.

* -S FORCEHTTPSPORTS: If this port is open, assume it is HTTPS regardless of
nmap's stated service name

* -H FORCEHTTPPORTS: If this port is open, assume it is HTTP regardless of
nmap's stated service name

* -v: Display version number and exit.

* -d: Turn on debug logging output.

# Copyright and License

Copyright (C) 2016 Hurricane Labs

nmurl was written by Steve Benson for Hurricane Labs.

nmurl is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 3, or (at your option) any later
version.

nmurl is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along with
this program; see the file LICENSE.  If not, see <http://www.gnu.org/licenses/>.
