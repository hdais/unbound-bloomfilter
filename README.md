  This patch implements a mitigation of random subdomain attack
against DNS resolver using bloomfilter.

  When DNS resolver operators suffer from random subdomain attack
they often block all queries for target domain (e.g. example.com) at their resolvers.
It mitigates the attack effectively but the resolver no longer
resolves example.com -- It is attacker's goal: DoS of example.com.

  This patch for unbound adds a new blocking mode "bloomfilter".
It learns QNAMEs which resulted in NOERROR using bloomfilter in peace time.
When you have set a domain to bloomfilter and Unbound receives queries
for that domain, it accepts only QNAMEs that matches to bloomfilter
(i.e. query result WAS NOERROR in past).

So it will effectively refuses only bad random queries
(bad query will result cache miss and NXDOMAIN).

# Enabling bloomfilter learning

  set these options in unbound.conf:

`bloomfilter-size`

  Size of bloomfilter's bitfield (in bytes). You need 9.6 bits
  per one NOERROR QNAMEs under 1% false positive.
  E.g. 1 billion (1,000,000,000) QNAMEs needs "1.2g".

  A plain number is in bytes, append 'k', 'm'  or  'g'
  for  kilobytes,  megabytes  or  gigabytes.

`bloomfilter-interval`

  BF is reset every this interval (in seconds).
  
## unbound.conf example
    server:
      bloomfilter-size: 1024m
      bloomfilter-interval: 86400


# To Protect unbound from damage caused by random subdomain attack

Specify domain(s) to protect by:

    $ unbound-control local_zone example.com bloomfilter
  
example.com is a domain which is under random subdomain attack.
  
# Automatic detection of domains under attack

this option in unbound.conf:

    bloomfilter-threshold

automatically applies bloomfilter to domains whose number of long-lived (> 1500 milliseconds) query
in requestlist exceeds `bloomfilter-threshold`.
  
## `unbound.conf` example
     server:
      bloomfilter-size: 1024m
      bloomfilter-interval: 86400
      bloomfilter-threshold: 100
