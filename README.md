  This implements a mitigation of random subdomain attack
against DNS resolver using bloomfilter.

  When DNS resolver operators suffers from random subdomain attack
they often block all queries for victim.com at their resolvers.
It mitigates attack effectively but the resolver no longer
resolves victim.com. 

  This patch for unbound adds a new blocking mode "softblock".
It learns QNAMEs resulted in NOERROR using bloomfilter at all time, and
if you applied a domain to softblock and unbound receives queries
for this domain it accepts only QNAMEs whose result was NOERROR in past.
So it will effectively refuses only bad random queries
(result will be cache miss and NXDOMAIN).

# To Enabe softblock bloomfilter learning

  set these options in unbound.conf:

`softblock-bf-size`

  Size of bloomfilter's bitfield (in bytes). You need 9.6 bits
  per one NOERROR QNAMEs under 1% false positive.
  i.e. 1 billion (1,000,000,000) QNAMEs needs 1.2g

`softblock-interval`

  BF is reset every this interval (in seconds).
  
## unbound.conf example
    server:
      softblock-bf-size: 1024m
      softblock-interval: 86400


# Protecting unbound from damage caused by random subdomain attack

    $ unbound-control local_zone victim.com softblock
  
  victim.com is a domain which is under random subdomain attack.


