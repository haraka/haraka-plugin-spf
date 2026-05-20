const assert = require('node:assert')
const { describe, it, before, after, beforeEach } = require('node:test')

const ipaddr = require('ipaddr.js')
const fixtures = require('haraka-test-fixtures')

const SPF = require('../lib/spf').SPF

SPF.prototype.log_debug = () => {} // noop, hush debug output

// A local fake DNS server (haraka-test-fixtures) serves these zones so the
// real node:dns -> SPF path is exercised deterministically, without the
// public-DNS flakiness the old gmail/aexp/facebook/google tests suffered.
const ZONES = {
  'pass.example': { txt: 'v=spf1 ip4:1.2.3.4 -all' },
  'fail.example': { txt: 'v=spf1 ip4:1.2.3.4 -all' },
  'softfail.example': { txt: 'v=spf1 ip4:1.2.3.4 ~all' },
  'inc.example': { txt: 'v=spf1 include:_spf.inc.example -all' },
  '_spf.inc.example': { txt: 'v=spf1 ip4:5.6.7.8 -all' },
  'redir.example': { txt: 'v=spf1 redirect=_spf.redir.example' },
  '_spf.redir.example': { txt: 'v=spf1 ip4:1.2.3.4 -all' },
  'mx.example': {
    mx: [
      { preference: 10, exchange: 'mail1.mx.example' },
      { preference: 20, exchange: 'mail2.mx.example' },
    ],
  },
  'mail1.mx.example': { a: ['1.1.1.1'] },
  'mail2.mx.example': { a: ['2.2.2.2'] },
  // 11 `a:` mechanisms — over the RFC 7208 §4.6.4 limit of 10.
  'limit11.example': {
    txt: 'v=spf1 a:n1.example a:n2.example a:n3.example a:n4.example a:n5.example a:n6.example a:n7.example a:n8.example a:n9.example a:n10.example a:match.example -all',
  },
  'n1.example': { a: ['9.9.9.9'] },
  'n2.example': { a: ['9.9.9.9'] },
  'n3.example': { a: ['9.9.9.9'] },
  'n4.example': { a: ['9.9.9.9'] },
  'n5.example': { a: ['9.9.9.9'] },
  'n6.example': { a: ['9.9.9.9'] },
  'n7.example': { a: ['9.9.9.9'] },
  'n8.example': { a: ['9.9.9.9'] },
  'n9.example': { a: ['9.9.9.9'] },
  'n10.example': { a: ['9.9.9.9'] },
  'match.example': { a: ['1.2.3.4'] },
  // Three `a:` mechanisms pointing at undefined names (NXDOMAIN). After
  // the third void lookup, RFC 7208 §4.6.4 requires PermError.
  'voidparent.example': {
    txt: 'v=spf1 a:vd1.example a:vd2.example a:vd3.example -all',
  },
  // vd1/vd2/vd3.example intentionally not defined -> NXDOMAIN
}

let dns, restore, spfInst

before(async () => {
  dns = await fixtures.dns.start(ZONES)
  // mech_mx() resolves MX via haraka-net-utils, which uses its own shared
  // resolver -- point that at the fake server too.
  restore = dns.patch(require('haraka-net-utils/lib/dns_config'))
})

after(async () => {
  restore()
  await dns.close()
})

beforeEach(() => {
  spfInst = new SPF()
  spfInst.resolver = dns.resolver()
})

describe('SPF', () => {
  it('new SPF', () => {
    assert.ok(spfInst)
  })

  it('constants', () => {
    assert.equal(1, spfInst.SPF_NONE)
    assert.equal(2, spfInst.SPF_PASS)
    assert.equal(3, spfInst.SPF_FAIL)
    assert.equal(4, spfInst.SPF_SOFTFAIL)
    assert.equal(5, spfInst.SPF_NEUTRAL)
    assert.equal(6, spfInst.SPF_TEMPERROR)
    assert.equal(7, spfInst.SPF_PERMERROR)
    assert.equal(10, spfInst.LIMIT)
  })

  it('mod_redirect, true', async () => {
    spfInst.been_there['example.com'] = true
    const rc = await spfInst.mod_redirect('example.com')
    assert.equal(1, rc)
  })

  it('mod_redirect, false', async () => {
    spfInst.count = 0
    spfInst.ip = '1.2.3.4'
    spfInst.mail_from = 'fraud@redir.example'

    const rc = await spfInst.mod_redirect('redir.example')
    assert.equal(rc, spfInst.SPF_PASS)
  })

  it('resolves more than one IP in mech_mx', async () => {
    spfInst.domain = 'mx.example'
    spfInst.ip_ver = 'ipv4'

    await spfInst.mech_mx()
    assert.equal(spfInst._found_mx_addrs.length, 2)
  })

  it('check_host, pass', async () => {
    spfInst.count = 0
    const rc = await spfInst.check_host(
      '1.2.3.4',
      'pass.example',
      'haraka@pass.example',
    )
    assert.equal(rc, spfInst.SPF_PASS, 'pass')
  })

  it('check_host, fail', async () => {
    spfInst.count = 0
    const rc = await spfInst.check_host(
      '9.9.9.9',
      'fail.example',
      'haraka@fail.example',
    )
    assert.equal(rc, spfInst.SPF_FAIL, 'fail')
  })

  it('check_host, softfail', async () => {
    spfInst.count = 0
    const rc = await spfInst.check_host(
      '9.9.9.9',
      'softfail.example',
      'haraka@softfail.example',
    )
    assert.equal(rc, spfInst.SPF_SOFTFAIL, 'soft fail')
  })

  it('valid_ip, true', () => {
    assert.equal(spfInst.valid_ip(':212.70.129.94'), true)
  })

  it('valid_ip, false', () => {
    assert.equal(spfInst.valid_ip(':212.70.d.94'), false)
  })

  it('sets spf_record includes', async () => {
    spfInst.count = 0
    const rc = await spfInst.check_host('5.6.7.8', 'inc.example')
    assert.equal(rc, spfInst.SPF_PASS, 'included record matched')
    assert.ok(spfInst.spf_record.includes('include:_spf.inc.example'))
  })

  it('mech_ptr escapes every dot in a multi-label domain', async () => {
    // Bug C1: `domain.replace('.', '\\.')` only escapes the first dot.
    // For domain `example.co.uk` the buggy regex becomes
    // /example\.co.uk$/i, where `.` between `co` and `uk` matches any
    // character. A reverse-lookup name like `evil.example.coXuk` (after
    // forward-confirmation) would then yield a false-positive MATCH.
    spfInst.count = 0
    spfInst.ip = '1.2.3.4'
    spfInst.ipaddr = ipaddr.parse('1.2.3.4')
    spfInst.ip_ver = 'ipv4'
    spfInst.domain = 'example.co.uk'
    spfInst.resolver = {
      reverse: async () => ['evil.example.coXuk'],
      resolve4: async () => ['1.2.3.4'],
    }
    const rc = await spfInst.mech_ptr('+', null)
    assert.equal(rc, spfInst.SPF_NONE)
  })

  it('mech_ptr only matches the domain itself or a subdomain', async () => {
    // A PTR ending in `evilexample.com` must not match domain `example.com`.
    spfInst.count = 0
    spfInst.ip = '1.2.3.4'
    spfInst.ipaddr = ipaddr.parse('1.2.3.4')
    spfInst.ip_ver = 'ipv4'
    spfInst.domain = 'example.com'
    spfInst.resolver = {
      reverse: async () => ['evilexample.com'],
      resolve4: async () => ['1.2.3.4'],
    }
    const rc = await spfInst.mech_ptr('+', null)
    assert.equal(rc, spfInst.SPF_NONE)
  })

  it('check_host returns TempError when a DNS lookup hangs past the timeout', async () => {
    // Bug S2: the plugin's outer hook timer bounds the whole hook, but
    // the SPF engine itself doesn't bound individual DNS operations.
    // A hanging resolver should be surfaced as TempError, not block
    // until the outer timer fires.
    const hung = new SPF()
    hung.dns_timeout_ms = 50
    hung.resolver = {
      resolveTxt: () => new Promise(() => {}),
    }
    const rc = await hung.check_host(
      '1.2.3.4',
      'hang.example',
      'a@hang.example',
    )
    assert.equal(rc, hung.SPF_TEMPERROR)
  })

  it('check_host returns PermError after 3 void lookups', async () => {
    // RFC 7208 §4.6.4: void lookups (NODATA / NXDOMAIN from a/mx/ptr/
    // exists/include/redirect) are limited to two. The third must yield
    // PermError. Without the fix, three NXDOMAIN `a:` mechanisms each
    // return SPF_NONE and evaluation falls through to `-all`, returning
    // Fail instead.
    spfInst.count = 0
    const rc = await spfInst.check_host(
      '1.2.3.4',
      'voidparent.example',
      'haraka@voidparent.example',
    )
    assert.equal(rc, spfInst.SPF_PERMERROR)
  })

  it('check_host returns PermError once the 10-lookup budget is exceeded', async () => {
    // Bug S1: the pre-mechanism lookup-limit check at the top of the loop
    // honors a mechanism result before re-checking the counter. An 11th
    // DNS-producing mechanism that yields Pass/Fail is returned even
    // though RFC 7208 §4.6.4 requires PermError once the budget is
    // exceeded. Eleven `a:` mechanisms where the 11th matches should
    // therefore return PermError, not Pass.
    spfInst.count = 0
    const rc = await spfInst.check_host(
      '1.2.3.4',
      'limit11.example',
      'haraka@limit11.example',
    )
    assert.equal(rc, spfInst.SPF_PERMERROR)
  })

  it('mech_include surfaces internal errors as TempError', async () => {
    // Bug C3: the catch in mech_include swallows internal errors and
    // returns undefined, which the caller then treats as falsy and
    // continues evaluating. A non-iterable from resolveTxt makes
    // recurse.check_host throw (its `for ... of` runs outside the
    // try/catch). The expected behaviour is a defined SPF status.
    spfInst.count = 0
    spfInst.ip = '1.2.3.4'
    spfInst.ip_ver = 'ipv4'
    spfInst.mail_from = 'test@inc.example'
    spfInst.resolver = {
      resolveTxt: async () => null,
    }
    const rc = await spfInst.mech_include('+', ':_spf.inc.example')
    assert.equal(rc, spfInst.SPF_TEMPERROR)
  })

  it('expand_macros %{p} uses p_name when set', () => {
    spfInst.helo = 'mail.example.com'
    spfInst.domain = 'example.com'
    spfInst.ip = '1.2.3.4'
    spfInst.mail_from = 'a@example.com'
    spfInst.p_name = 'mta.sender.example'
    assert.equal(spfInst.expand_macros('%{p}'), 'mta.sender.example')
  })

  it('expand_macros %{p} falls back to "unknown" when p_name is not set', () => {
    spfInst.helo = 'mail.example.com'
    spfInst.domain = 'example.com'
    spfInst.ip = '1.2.3.4'
    spfInst.mail_from = 'a@example.com'
    assert.equal(spfInst.expand_macros('%{p}'), 'unknown')
  })

  it('mech_ptr still matches a real subdomain', async () => {
    spfInst.count = 0
    spfInst.ip = '1.2.3.4'
    spfInst.ipaddr = ipaddr.parse('1.2.3.4')
    spfInst.ip_ver = 'ipv4'
    spfInst.domain = 'example.co.uk'
    spfInst.resolver = {
      reverse: async () => ['mail.example.co.uk'],
      resolve4: async () => ['1.2.3.4'],
    }
    const rc = await spfInst.mech_ptr('+', null)
    assert.equal(rc, spfInst.SPF_PASS)
  })
})
