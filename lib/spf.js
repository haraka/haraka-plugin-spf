'use strict'
// spf

const dns = require('node:dns/promises')
const net = require('node:net')
const ipaddr = require('ipaddr.js')
const net_utils = require('haraka-net-utils')

class SPF {
  constructor(count, been_there) {
    // For macro expansion
    // This should be set before check_host() is called
    this.helo = 'unknown'
    this.spf_record = ''

    // RFC 4408 Section 10.1
    // Limit the number of mechanisms/modifiers that require DNS lookups to complete.
    this.count = 0

    // If we have recursed we are supplied the count
    if (count) this.count = count

    // Prevent circular references, this isn't covered in the RFC
    this.been_there = {}
    if (been_there) this.been_there = been_there

    // RFC 4408 Section 10.1
    this.LIMIT = 10

    // Constants
    this.SPF_NONE = 1
    this.SPF_PASS = 2
    this.SPF_FAIL = 3
    this.SPF_SOFTFAIL = 4
    this.SPF_NEUTRAL = 5
    this.SPF_TEMPERROR = 6
    this.SPF_PERMERROR = 7

    this.mech_ip4 = this.mech_ip
    this.mech_ip6 = this.mech_ip

    // Used for tests only
    this._found_mx_addrs = []
  }

  const_translate(value) {
    const t = {}
    for (const k in this) {
      if (typeof this[k] === 'number') {
        t[this[k]] = k.toUpperCase()
      }
    }
    if (t[value]) return t[value]
    return 'UNKNOWN'
  }

  result(value) {
    switch (value) {
      case this.SPF_NONE:
        return 'None'
      case this.SPF_PASS:
        return 'Pass'
      case this.SPF_FAIL:
        return 'Fail'
      case this.SPF_SOFTFAIL:
        return 'SoftFail'
      case this.SPF_NEUTRAL:
        return 'Neutral'
      case this.SPF_TEMPERROR:
        return 'TempError'
      case this.SPF_PERMERROR:
        return 'PermError'
      default:
        return `Unknown (${value})`
    }
  }

  return_const(qualifier) {
    switch (qualifier) {
      case '+':
        return this.SPF_PASS
      case '-':
        return this.SPF_FAIL
      case '~':
        return this.SPF_SOFTFAIL
      case '?':
        return this.SPF_NEUTRAL
      default:
        return this.SPF_PERMERROR
    }
  }

  expand_macros(str) {
    const macro = /%{([slodipvh])((?:(?:\d+)?r?)?)?([-.+,/_=])?}/gi
    let match
    while ((match = macro.exec(str))) {
      // match[1] = macro-letter
      // match[2] = transformers
      // match[3] = delimiter
      if (!match[3]) match[3] = '.'
      let strip = /(\d+)/.exec(match[2])
      if (strip) strip = strip[1]

      const reverse = `${match[2]}`.indexOf('r') !== -1
      let replace
      let kind
      switch (match[1]) {
        case 's': // sender
          replace = this.mail_from
          break
        case 'l': // local-part of sender
          replace = this.mail_from.split('@')[0]
          break
        case 'o': // domain of sender
          replace = this.mail_from.split('@')[1]
          break
        case 'd': // domain
          replace = this.domain
          break
        case 'i': // IP
          replace = this.ip
          break
        case 'p': // validated domain name of IP
          // NOT IMPLEMENTED
          replace = 'unknown'
          break
        case 'v': // IP version
          try {
            if (this.ip_ver === 'ipv4') kind = 'in-addr'
            if (this.ip_ver === 'ipv6') kind = 'ip6'
            replace = kind
          } catch (e) {}
          break
        case 'h': // EHLO/HELO domain
          replace = this.helo
          break
      }
      // Process any transformers
      if (replace) {
        if (reverse || strip) {
          replace = replace.split(match[3])
          if (strip) {
            strip = strip > replace.length ? replace.length : strip
            replace = replace.slice(0, strip)
          }
          if (reverse) replace = replace.reverse()
          replace = replace.join('.')
        }
        str = str.replace(match[0], replace)
      }
    }
    // Process any other expansions
    return str.replace(/%%/g, '%').replace(/%_/g, ' ').replace(/%-/g, '%20')
  }

  log_debug(str) {
    console.error(str)
  }

  valid_ip(ip) {
    const ip_split = /^:([^/ ]+)(?:\/([^ ]+))?$/.exec(ip)
    if (!ip_split) {
      this.log_debug(`invalid IP address: ${ip}`)
      return false
    }
    if (!ipaddr.isValid(ip_split[1])) {
      this.log_debug(`invalid IP address: ${ip_split[1]}`)
      return false
    }
    return true
  }

  async check_host(ip, domain, mail_from) {
    domain = domain.toLowerCase()
    mail_from = mail_from ? mail_from.toLowerCase() : `postmaster@${domain}`
    this.ipaddr = ipaddr.parse(ip)
    this.ip_ver = this.ipaddr.kind()
    if (this.ip_ver === 'ipv6') {
      this.ip = this.ipaddr.toString()
    } else {
      this.ip = ip
    }
    this.domain = domain
    this.mail_from = mail_from

    this.log_debug(`ip=${ip} domain=${domain} mail_from=${mail_from}`)

    const mech_array = []
    const mod_array = []

    // Get the SPF record for domain
    let txt_rrs
    try {
      txt_rrs = await dns.resolveTxt(domain)
    } catch (err) {
      this.log_debug(`error looking up TXT record: ${err.message}`)
      switch (err.code) {
        case dns.NOTFOUND:
        case dns.NODATA:
        case dns.NXDOMAIN:
          return this.SPF_NONE
        default:
          return this.SPF_TEMPERROR
      }
    }

    let spf_record
    let match
    for (let txt_rr of txt_rrs) {
      // txt_rr might be an array, so handle that case
      if (Array.isArray(txt_rr)) {
        txt_rr = txt_rr.join('')
      }

      match = /^(v=spf1(?:$|\s.+$))/i.exec(txt_rr)
      if (!match) {
        this.log_debug(`discarding TXT record: ${txt_rr}`)
        continue
      }

      if (!spf_record) {
        this.log_debug(`found SPF record for domain ${domain}: ${match[1]}`)
        spf_record = match[1].replace(/\s+/, ' ').toLowerCase()
      } else {
        this.log_debug(
          `found additional SPF record for domain ${domain}: ${match[1]}`,
        )
        return this.SPF_PERMERROR
      }
    }

    if (!spf_record) return this.SPF_NONE // No SPF record?

    // Store the SPF record used in the object
    this.spf_record = spf_record

    // Validate SPF record and build call chain
    const mech_regexp1 = /^([-+~?])?(all|a|mx|ptr)$/
    const mech_regexp2 =
      /^([-+~?])?(a|mx|ptr|ip4|ip6|include|exists)((?::[^/ ]+(?:\/\d+(?:\/\/\d+)?)?)|\/\d+(?:\/\/\d+)?)$/
    const mod_regexp = /^([^ =]+)=([a-z0-9:/._-]+)$/
    const split = spf_record.split(' ')

    for (const mechanism of split) {
      if (!mechanism) continue // Skip blanks

      const obj = {}
      if (
        (match = mech_regexp1.exec(mechanism) || mech_regexp2.exec(mechanism))
      ) {
        // match:  1=qualifier, 2=mechanism, 3=optional args
        if (!match[1]) match[1] = '+'
        this.log_debug(`found mechanism: ${match}`)

        if (match[2] === 'ip4' || match[2] === 'ip6') {
          if (!this.valid_ip(match[3])) return this.SPF_PERMERROR
        } else {
          // Validate macro strings
          if (match[3] && /%[^{%+-]/.exec(match[3])) {
            this.log_debug('invalid macro string')
            return this.SPF_PERMERROR
          }
          if (match[3]) {
            // Expand macros
            match[3] = this.expand_macros(match[3])
          }
        }

        obj[match[2]] = [match[1], match[3]]
        mech_array.push(obj)
        // console.log(mech_array)
      } else if ((match = mod_regexp.exec(mechanism))) {
        this.log_debug(`found modifier: ${match}`)
        // match[1] = modifier
        // match[2] = name
        // Make sure we have a method
        if (!this[`mod_${match[1]}`]) {
          this.log_debug(`skipping unknown modifier: ${match[1]}`)
        } else {
          obj[match[1]] = match[2]
          mod_array.push(obj)
          // console.log(mod_array)
        }
      } else {
        // Syntax error
        this.log_debug(`syntax error: ${mechanism}`)
        return this.SPF_PERMERROR
      }
    }

    this.log_debug(`SPF record for '${this.domain}' validated OK`)

    // Run all the mechanisms first
    for (const mech of mech_array) {
      const func = Object.keys(mech)
      const args = mech[func]
      // console.log(`running mechanism: ${func} args=${args} domain=${this.domain}`);
      this.log_debug(
        `running mechanism: ${func} args=${args} domain=${this.domain}`,
      )

      if (this.count > this.LIMIT) {
        this.log_debug('lookup limit reached')
        return this.SPF_PERMERROR
      }

      const result = await this[`mech_${func}`](
        args && args.length ? args[0] : null,
        args && args.length ? args[1] : null,
      )
      // console.log(result)

      // If we have a result other than SPF_NONE
      if (result && result !== this.SPF_NONE) return result
    }

    // run any modifiers
    for (const mod of mod_array) {
      const func = Object.keys(mod)
      const args = mod[func]
      this.log_debug(
        `running modifier: ${func} args=${args} domain=${this.domain}`,
      )
      const result = await this[`mod_${func}`](args)

      // Check limits
      if (this.count > this.LIMIT) {
        this.log_debug('lookup limit reached')
        return this.SPF_PERMERROR
      }

      // Return any result that is not SPF_NONE
      if (result && result !== this.SPF_NONE) return result
    }

    return this.SPF_NEUTRAL // default if no more mechanisms
  }

  async mech_all(qualifier) {
    return this.return_const(qualifier)
  }

  async mech_include(qualifier, args) {
    const domain = args.substr(1)
    // Avoid circular references
    if (this.been_there[domain]) {
      this.log_debug(`circular reference detected: ${domain}`)
      return this.SPF_NONE
    }
    this.count++
    this.been_there[domain] = true
    // Recurse
    const recurse = new SPF(this.count, this.been_there)
    try {
      const result = await recurse.check_host(this.ip, domain, this.mail_from)
      this.log_debug(
        `mech_include: domain=${domain} returned=${this.const_translate(result)}`,
      )
      switch (result) {
        case this.SPF_PASS:
          return this.SPF_PASS
        case this.SPF_FAIL:
        case this.SPF_SOFTFAIL:
        case this.SPF_NEUTRAL:
          return this.SPF_NONE
        case this.SPF_TEMPERROR:
          return this.SPF_TEMPERROR
        default:
          return this.SPF_PERMERROR
      }
    } catch (err) {
      // ignore
    }
  }

  async mech_exists(qualifier, args) {
    this.count++
    const exists = args.substr(1)

    try {
      const addrs = await dns.resolve(exists)
      this.log_debug(`mech_exists: ${exists} result=${addrs.join(',')}`)
      return this.return_const(qualifier)
    } catch (err) {
      this.log_debug(`mech_exists: ${err}`)
      switch (err.code) {
        case dns.NOTFOUND:
        case dns.NODATA:
        case dns.NXDOMAIN:
          return this.SPF_NONE
        default:
          return this.SPF_TEMPERROR
      }
    }
  }

  async mech_a(qualifier, args) {
    this.count++
    // Parse any arguments
    let cm
    let cidr4
    let cidr6
    if (args && (cm = /\/(\d+)(?:\/\/(\d+))?$/.exec(args))) {
      cidr4 = cm[1]
      cidr6 = cm[2]
    }
    let dm
    let domain = this.domain
    if (args && (dm = /^:([^/ ]+)/.exec(args))) {
      domain = dm[1]
    }
    // Calculate with IP method to use
    let resolve_method
    let cidr
    if (this.ip_ver === 'ipv4') {
      cidr = cidr4
      resolve_method = 'resolve4'
    } else if (this.ip_ver === 'ipv6') {
      cidr = cidr6
      resolve_method = 'resolve6'
    }
    // Use current domain
    let addrs
    try {
      addrs = await dns[resolve_method](domain)
    } catch (err) {
      this.log_debug(`mech_a: ${err}`)
      switch (err.code) {
        case dns.NOTFOUND:
        case dns.NODATA:
        case dns.NXDOMAIN:
          return this.SPF_NONE
        default:
          return this.SPF_TEMPERROR
      }
    }

    if (!addrs) return this.SPF_NONE

    for (const addr of addrs) {
      if (cidr) {
        // CIDR
        const range = ipaddr.parse(addr)
        if (this.ipaddr.match(range, cidr)) {
          this.log_debug(`mech_a: ${this.ip} => ${addr}/${cidr}: MATCH!`)
          return this.return_const(qualifier)
        } else {
          this.log_debug(`mech_a: ${this.ip} => ${addr}/${cidr}: NO MATCH`)
        }
      } else {
        if (addr === this.ip) {
          return this.return_const(qualifier)
        } else {
          this.log_debug(`mech_a: ${this.ip} => ${addr}: NO MATCH`)
        }
      }
    }
    return this.SPF_NONE
  }

  async mech_mx(qualifier, args) {
    this.count++
    // Parse any arguments
    let cm
    let cidr4
    let cidr6
    if (args && (cm = /\/(\d+)((?:\/\/(\d+))?)$/.exec(args))) {
      cidr4 = cm[1]
      cidr6 = cm[2]
    }
    let dm
    let domain = this.domain
    if (args && (dm = /^:([^/ ]+)/.exec(args))) {
      domain = dm[1]
    }
    // Fetch the MX records for the specified domain
    let mxes
    try {
      mxes = await net_utils.get_mx(domain)
      mxes = mxes.filter((mx) => !net.isIP(mx.exchange)) // remove implicit MX
    } catch (err) {
      switch (err.code) {
        case dns.NOTFOUND:
        case dns.NODATA:
        case dns.NXDOMAIN:
          return this.SPF_NONE
        default:
          return this.SPF_TEMPERROR
      }
    }

    let addresses = []
    // RFC 4408 Section 10.1
    if (mxes.length > this.LIMIT) return this.SPF_PERMERROR

    let cidr
    for (const element of mxes) {
      const mx = element.exchange
      // Calculate which IP method to use
      let resolve_method
      if (this.ip_ver === 'ipv4') {
        cidr = cidr4
        resolve_method = 'resolve4'
      } else if (this.ip_ver === 'ipv6') {
        cidr = cidr6
        resolve_method = 'resolve6'
      }

      let addrs
      try {
        addrs = await dns[resolve_method](mx)
      } catch (err) {
        switch (err.code) {
          case dns.NOTFOUND:
          case dns.NODATA:
          case dns.NXDOMAIN:
            break
          default:
            return this.SPF_TEMPERROR
        }
      }

      this.log_debug(`mech_mx: mx=${mx} addresses=${addrs?.join(',')}`)
      addresses = addrs ? addrs.concat(addresses) : [];
    }

    if (!addresses.length) return this.SPF_NONE
    this._found_mx_addrs = addresses

    // All queries run; see if our IP matches
    if (cidr) {
      // CIDR match type
      for (const address of addresses) {
        const range = ipaddr.parse(address)
        if (this.ipaddr.match(range, cidr)) {
          this.log_debug(`mech_mx: ${this.ip} => ${address}/${cidr}: MATCH!`)
          return this.return_const(qualifier)
        } else {
          this.log_debug(`mech_mx: ${this.ip} => ${address}/${cidr}: NO MATCH`)
        }
      }
      // No matches
      return this.SPF_NONE
    } else {
      if (addresses.includes(this.ip)) {
        this.log_debug(`mech_mx: ${this.ip} => ${addresses.join(',')}: MATCH!`)
        return this.return_const(qualifier)
      } else {
        this.log_debug(
          `mech_mx: ${this.ip} => ${addresses.join(',')}: NO MATCH`,
        )
        return this.SPF_NONE
      }
    }
  }

  async mech_ptr(qualifier, args) {
    this.count++
    let dm
    let domain = this.domain
    if (args && (dm = /^:([^/ ]+)/.exec(args))) {
      domain = dm[1]
    }
    // First do a PTR lookup for the connecting IP
    let ptrs
    try {
      ptrs = await dns.reverse(this.ip)
    } catch (err) {
      this.log_debug(`mech_ptr: lookup=${this.ip} => ${err}`)
      return this.SPF_NONE
    }

    let resolve_method
    if (this.ip_ver === 'ipv4') resolve_method = 'resolve4'
    if (this.ip_ver === 'ipv6') resolve_method = 'resolve6'
    const names = []
    // RFC 4408 Section 10.1
    if (ptrs.length > this.LIMIT) return this.SPF_PERMERROR

    for (const ptr of ptrs) {
      try {
        const addrs = await dns[resolve_method](ptr)
        for (const addr of addrs) {
          if (addr === this.ip) {
            this.log_debug(`mech_ptr: ${this.ip} => ${ptr} => ${addr}: MATCH!`)
            names.push(ptr.toLowerCase())
          } else {
            this.log_debug(
              `mech_ptr: ${this.ip} => ${ptr} => ${addr}: NO MATCH`,
            )
          }
        }
      } catch (err) {
        // Skip on error
        this.log_debug(`mech_ptr: lookup=${ptr} => ${err}`)
        continue
      }
    }

    // Finished
    // Catch bogus PTR matches e.g. ptr:*.bahnhof.se (should be ptr:bahnhof.se)
    // These will cause a regexp error, so we can catch them.
    try {
      const re = new RegExp(`${domain.replace('.', '\\.')}$`, 'i')
      for (const name of names) {
        if (re.test(name)) {
          this.log_debug(`mech_ptr: ${name} => ${domain}: MATCH!`)
          return this.return_const(qualifier)
        } else {
          this.log_debug(`mech_ptr: ${name} => ${domain}: NO MATCH`)
        }
      }
      return this.SPF_NONE
    } catch (e) {
      this.log_debug('mech_ptr', { domain: this.domain, err: e.message })
      return this.SPF_PERMERROR
    }
  }

  async mech_ip(qualifier, args) {
    const cidr = args.substr(1)
    const match = /^([^/ ]+)(?:\/(\d+))?$/.exec(cidr)
    if (!match) return this.SPF_NONE

    // match[1] == ip
    // match[2] == mask
    try {
      if (!match[2]) {
        // Default masks for each IP version
        if (this.ip_ver === 'ipv4') match[2] = '32'
        if (this.ip_ver === 'ipv6') match[2] = '128'
      }
      const range = ipaddr.parse(match[1])
      const rtype = range.kind()
      if (this.ip_ver !== rtype) {
        this.log_debug(`mech_ip: ${this.ip} => ${cidr}: SKIP`)
        return this.SPF_NONE
      }
      if (this.ipaddr.match(range, match[2])) {
        this.log_debug(`mech_ip: ${this.ip} => ${cidr}: MATCH!`)
        return this.return_const(qualifier)
      } else {
        this.log_debug(`mech_ip: ${this.ip} => ${cidr}: NO MATCH`)
      }
    } catch (e) {
      this.log_debug(e.message)
      return this.SPF_PERMERROR
    }
    return this.SPF_NONE
  }

  async mod_redirect(domain) {
    // Avoid circular references
    if (this.been_there[domain]) {
      this.log_debug(`circular reference detected: ${domain}`)
      return this.SPF_NONE
    }
    this.count++
    this.been_there[domain] = 1
    return await this.check_host(this.ip, domain, this.mail_from)
  }

  async mod_exp() {
    // NOT IMPLEMENTED
    return this.SPF_NONE
  }

  async mod_v() {
    return this.SPF_NONE
  }
}

exports.SPF = SPF
