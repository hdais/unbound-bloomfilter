  This patch implements a mitigation of random subdomain attack against DNS resolver using Bloomfilter.

  When DNS resolver operators suffer from random subdomain attack they often block all queries for target domain (e.g. `example.com`) at their resolvers. It mitigates the attack effectively but the resolver no longer resolves `example.com` -- It is attacker's goal: DoS of `example.com`.

  This patch for unbound adds a new blocking mode `bloomfilter`. It learns QNAMEs which resulted in NOERROR (existing QNAMEs) using Bloomfilter in peace time. When you have set a domain to bloomfilter and Unbound receives queries for that domain, it accepts only QNAMEs that matches to Bloomfilter (whose result was NOERROR in past). So it can effectively refuse only bad random queries which will be NXDOMAIN.

# Enabling bloomfilter learning

  set these options in unbound.conf:

`bloomfilter-size`

  Size of Bloomfilter's bitfield (in bytes). You need 9.6 bits per one NOERROR QNAMEs under 1% false positive.
  E.g. 1 billion (1,000,000,000) QNAMEs need "1.2g".

  A plain number is in bytes, append 'k', 'm'  or  'g' for  kilobytes,  megabytes  or  gigabytes.

`bloomfilter-interval`

  BF is reset every this interval (in seconds).
  
Note that actually two (2) Bloomfilter bitfields are allocated. So if you specify `bloomfilter-size: 1024m` it allocates 2048Mbytes. In first interval it writes to first field. In second interval it writes to second field. And in beginning of third interval it clears first field and start writing to first field. 

## unbound.conf example
    server:
      bloomfilter-size: 1024m
      bloomfilter-interval: 86400


# To Protect unbound from damage caused by random subdomain attack (manually)

Specify domain(s) to protect by:

    $ unbound-control local_zone example.com bloomfilter
  
`example.com` is the domain under random subdomain attack.
  
# Automatic detection of domains under attack

this option in unbound.conf:

    bloomfilter-threshold

automatically applies bloomfilter to domains whose number of long-lived (> 1500 milliseconds) query in requestlist exceeds `bloomfilter-threshold`.

## How domain under attack is detected

The detection algorithm periodically scans requestlist. For example these query is in requestlist:

    QNAME                     elapsed time (in secs)
    ------------------------------------------------------
    qvsfwf.www.example1.com   0.3
    wrrt4f.www.example1.com   4.5
    twgett.www.example1.com   2.1
    jqfajr.www.example1.com   2.1
    www.example2.co.uk        2.1
    www.example3.info         1.2

It sums up number of long-lived qnames per domain. Public suffix list is used to classify "domain".

    domain          num_of_longlived_queries
    -----------------------------
    example1.com    3
    example2.co.uk  1

And it bloomfilters the domains whose `num_of_longlived_queries` exceeds `bloomfilter-threshold`. If a domain was already bloomfiltered and `num_of_longlived_queries` exceeds `bloomfilter-threshold * 2` (i.e. bloomfilter is not effective for any reason) it refuses ALL queries for the domain.

## `unbound.conf` example
     server:
      bloomfilter-size: 1024m
      bloomfilter-interval: 86400
      bloomfilter-threshold: 100
