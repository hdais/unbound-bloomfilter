  This patch implements a mitigation of random subdomain attack against DNS resolver using Bloomfilter.

  When DNS resolver operators suffer from random subdomain attack they often block all queries for target domain (e.g. `example.com`) at their resolvers. It mitigates the attack effectively but the resolver no longer resolves `example.com` -- It is attacker's goal: DoS of `example.com`.

  This patch for unbound implements a new blocking mode `bloomfilter`. It learns QNAMEs which resulted in NOERROR (existing domain name) using Bloomfilter in peace time. When a domain is set to be bloomfiltered (manually or automatically) and Unbound receives queries for that domain, it accepts only QNAMEs that matches to Bloomfilter (the query result was NOERROR in past). So it can effectively refuse only bad random queries which will be NXDOMAIN.

# To Enabling Bloomfilter Learning

  set these options in unbound.conf:

`bloomfilter-size`

  Size of Bloomfilter's bitfield (in bytes). You need 9.6 bits per one NOERROR QNAMEs under 1% false positive.
  E.g. 1 billion (1,000,000,000) QNAMEs need "1.2g".

  A plain number is in bytes, append 'k', 'm'  or  'g' for  kilobytes,  megabytes  or  gigabytes.

`bloomfilter-interval`

  BF is reset every this interval (in seconds).
  
Note that actually two (2) Bloomfilter bitfields are allocated. So if you specify `bloomfilter-size: 1024m` it allocates 2048M bytes memory. In first interval it writes to first field. In second interval it writes to second field. And in beginning of third interval it clears first field and start writing to first field. 

## unbound.conf example
    server:
      bloomfilter-size: 1024m
      bloomfilter-interval: 86400


# To Protect Unbound (and attacked domain) from random subdomain attack

## Setting bloomfiltered domains manually

    $ unbound-control local_zone example.com bloomfilter

Removing filtered domains:

    $ unbound-control local_zone_remove example.com
  
## Automatic detection of domains under attack

This option in unbound.conf:

    bloomfilter-threshold

automatically applies bloomfilter to domains whose number of long-lived (> 1.5 seconds) query in requestlist exceeds `bloomfilter-threshold`.

### The detection algorithm

The detection algorithm periodically scans requestlist. Suppose that these client queries is in requestlist:

    QNAME                     elapsed time (in secs)
    ------------------------------------------------------
    qvsfwf.www.example1.com   0.3
    wrrt4f.www.example1.com   4.5
    twgett.www.example1.com   2.1
    jqfajr.www.example1.com   2.1
    www.example2.co.uk        2.1
    www.example3.info         1.2

It sums up number of long-lived (elapsed time > 1.5) qnames per domain. Public suffix list is used to classify domains.

    domain          num_of_longlived_queries
    -----------------------------
    example1.com    3
    example2.co.uk  1

And it bloomfilters the domains whose `num_of_longlived_queries` exceeds `bloomfilter-threshold`. If a domain was already bloomfiltered and its `num_of_longlived_queries` exceeds `bloomfilter-threshold * 2` (bloomfilter is not effective for any reason) ALL queries for the domain is refused.

### `unbound.conf` example
     server:
      bloomfilter-size: 1024m
      bloomfilter-interval: 86400
      bloomfilter-threshold: 100
