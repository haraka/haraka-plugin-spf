const assert = require('node:assert')
const { describe, it, before, after, beforeEach } = require('node:test')

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
})
