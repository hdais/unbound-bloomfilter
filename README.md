  This patch implements a mitigation of random subdomain attack
against DNS resolver using bloomfilter.

  When DNS resolver operators suffers from random subdomain attack
they often block all queries for victim.com at their resolvers.
It mitigates the attack effectively but the resolver no longer
resolves victim.com -- It is attacker's goal: DoS of victim.com.

  This patch for unbound adds a new blocking mode "softblock".
It learns QNAMEs which resulted in NOERROR using bloomfilter at all time.
If you have set a domain to softblock and Unbound receives queries
for this domain, it accepts only QNAMEs that matches to bloomfilter -- 
i.e. query result was NOERROR in past.

So it will effectively refuses only bad random queries
(bad query will result cache miss and NXDOMAIN).

# Enabling softblock bloomfilter learning

  set these options in unbound.conf:

`softblock-bf-size`

  Size of bloomfilter's bitfield (in bytes). You need 9.6 bits
  per one NOERROR QNAMEs under 1% false positive.
  E.g. 1 billion (1,000,000,000) QNAMEs needs "1.2g".

  A plain number is in bytes, append 'k', 'm'  or  'g'
  for  kilobytes,  megabytes  or  gigabytes.

`softblock-interval`

  BF is reset every this interval (in seconds).
  
## unbound.conf example
    server:
      softblock-bf-size: 1024m
      softblock-interval: 86400


# Protecting unbound from damage caused by random subdomain attack

    $ unbound-control local_zone victim.com softblock
  
  victim.com is a domain which is under random subdomain attack.
