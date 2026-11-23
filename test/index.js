// node.js built-in modules
const assert = require('node:assert')
const { describe, it, beforeEach } = require('node:test')

// npm modules
const { Address } = require('@haraka/email-address')
const constants = require('haraka-constants')
const { makeConnection, makePlugin } = require('haraka-test-fixtures')

const SPF = require('../lib/spf').SPF
const spf = new SPF()

let plugin
let connection

beforeEach(() => {
  plugin = makePlugin('spf', { register: false })

  plugin.timeout = 8000
  plugin.load_spf_ini()

  // comment this line to see detailed SPF evaluation
  plugin.SPF.prototype.log_debug = () => {}

  connection = makeConnection({ withTxn: true })
})

describe('spf', () => {
  it('loads', () => {
    assert.ok(plugin)
  })
})

describe('load_spf_ini', () => {
  it('loads spf.ini from config/spf.ini', () => {
    plugin.load_spf_ini()
    assert.ok(plugin.cfg.main)
  })
})

describe('_configure_spf', () => {
  it('copies a validated fcrdns name into spf.p_name', () => {
    const conn = {
      results: {
        get: (name) =>
          name === 'fcrdns' ? { fcrdns: ['mta.sender.example'] } : null,
      },
    }
    const out = plugin._configure_spf(new SPF(), conn)
    assert.equal(out.p_name, 'mta.sender.example')
  })

  it('leaves p_name undefined when fcrdns has no validated names', () => {
    const conn = {
      results: { get: () => ({ fcrdns: [] }) },
    }
    const out = plugin._configure_spf(new SPF(), conn)
    assert.equal(out.p_name, undefined)
  })

  it('is safe when connection has no results store', () => {
    const out = plugin._configure_spf(new SPF(), undefined)
    assert.equal(out.p_name, undefined)
  })
})

describe('return_results', () => {
  it('result, none, reject=false', (t, done) => {
    plugin.cfg.deny.mfrom_none = false
    plugin.return_results(
      function next() {
        assert.equal(undefined, arguments[0])
        done()
      },
      connection,
      spf,
      'mfrom',
      spf.SPF_NONE,
      'test@example.com',
    )
  })

  it('result, none, reject=true', (t, done) => {
    plugin.cfg.deny.mfrom_none = true
    plugin.return_results(
      function next() {
        assert.equal(DENY, arguments[0])
        done()
      },
      connection,
      spf,
      'mfrom',
      spf.SPF_NONE,
      'test@example.com',
    )
  })

  it('result, neutral', (t, done) => {
    plugin.return_results(
      function next() {
        assert.equal(undefined, arguments[0])
        done()
      },
      connection,
      spf,
      'mfrom',
      spf.SPF_NEUTRAL,
      'test@example.com',
    )
  })

  it('result, pass', (t, done) => {
    plugin.return_results(
      function next() {
        assert.equal(undefined, arguments[0])
        done()
      },
      connection,
      spf,
      'mfrom',
      spf.SPF_PASS,
      'test@example.com',
    )
  })

  it('result, softfail, reject=false', (t, done) => {
    plugin.cfg.deny.mfrom_softfail = false
    plugin.return_results(
      function next() {
        assert.equal(undefined, arguments[0])
        done()
      },
      connection,
      spf,
      'mfrom',
      spf.SPF_SOFTFAIL,
      'test@example.com',
    )
  })

  it('result, softfail, reject=true', (t, done) => {
    plugin.cfg.deny.mfrom_softfail = true
    plugin.return_results(
      function next() {
        assert.equal(DENY, arguments[0])
        done()
      },
      connection,
      spf,
      'mfrom',
      spf.SPF_SOFTFAIL,
      'test@example.com',
    )
  })

  it('result, fail, reject=false', (t, done) => {
    plugin.cfg.deny.mfrom_fail = false
    plugin.return_results(
      function next() {
        assert.equal(undefined, arguments[0])
        done()
      },
      connection,
      spf,
      'mfrom',
      spf.SPF_FAIL,
      'test@example.com',
    )
  })

  it('result, fail, reject=true', (t, done) => {
    plugin.cfg.deny.mfrom_fail = true
    plugin.return_results(
      function next() {
        assert.equal(DENY, arguments[0])
        done()
      },
      connection,
      spf,
      'mfrom',
      spf.SPF_FAIL,
      'test@example.com',
    )
  })

  it('result, temperror, reject=false', (t, done) => {
    plugin.cfg.defer.mfrom_temperror = false
    plugin.return_results(
      function next() {
        assert.equal(undefined, arguments[0])
        done()
      },
      connection,
      spf,
      'mfrom',
      spf.SPF_TEMPERROR,
      'test@example.com',
    )
  })

  it('result, temperror, reject=true', (t, done) => {
    plugin.cfg.defer.mfrom_temperror = true
    plugin.return_results(
      function next() {
        assert.equal(DENYSOFT, arguments[0])
        done()
      },
      connection,
      spf,
      'mfrom',
      spf.SPF_TEMPERROR,
      'test@example.com',
    )
  })

  it('result, permerror, reject=false', (t, done) => {
    plugin.cfg.deny.mfrom_permerror = false
    plugin.return_results(
      function next() {
        assert.equal(undefined, arguments[0])
        done()
      },
      connection,
      spf,
      'mfrom',
      spf.SPF_PERMERROR,
      'test@example.com',
    )
  })

  it('result, permerror, reject=true', (t, done) => {
    plugin.cfg.deny.mfrom_permerror = true
    plugin.return_results(
      function next() {
        assert.equal(DENY, arguments[0])
        done()
      },
      connection,
      spf,
      'mfrom',
      spf.SPF_PERMERROR,
      'test@example.com',
    )
  })

  it('result, unknown', (t, done) => {
    plugin.return_results(
      function next() {
        assert.equal(undefined, arguments[0])
        done()
      },
      connection,
      spf,
      'mfrom',
      'unknown',
      'test@example.com',
    )
  })
})

describe('save_to_header', () => {
  const saveHeader = (ip) => {
    connection = makeConnection({ withTxn: true, ip: '172.16.16.14' })
    connection.set('hello.host', 'vhost0.example.com')
    plugin.save_to_header(
      connection,
      spf,
      spf.SPF_PASS,
      'user@example.com',
      'example.com',
      'mailfrom',
      ip,
    )
    return connection.transaction.header.get('Received-SPF')
  }

  it('names the checked IP when it differs from the client IP', () => {
    const header = saveHeader('66.128.51.165')
    assert.match(header, /designates 66\.128\.51\.165 as permitted sender/)
    assert.match(header, /client-ip=66\.128\.51\.165/)
    assert.doesNotMatch(header, /172\.16\.16\.14/)
  })

  it('names the client IP by default', () => {
    const header = saveHeader()
    assert.match(header, /designates 172\.16\.16\.14 as permitted sender/)
    assert.match(header, /client-ip=172\.16\.16\.14/)
  })
})

describe('hook_helo', () => {
  it('rfc1918', (t, done) => {
    let completed = 0
    function next(rc) {
      completed++
      assert.equal(undefined, rc)
      if (completed >= 2) done()
    }
    connection.remote.is_private = true
    plugin.helo_spf(next, connection)
    plugin.helo_spf(next, connection, 'helo.sender.com')
  })

  it('IPv4 literal', (t, done) => {
    connection = makeConnection({ withTxn: true, ip: '190.168.1.1' })
    plugin.helo_spf(
      function next(rc) {
        assert.equal(undefined, rc)
        done()
      },
      connection,
      '[190.168.1.1]',
    )
  })

  it('MX with no A record', { timeout: 5000 }, (t, done) => {
    connection = makeConnection({ withTxn: true, ip: '192.0.2.0' })
    plugin.helo_spf(
      function next(rc) {
        assert.equal(undefined, rc)
        done()
      },
      connection,
      'test.haraka.tnpi.net',
    )
  })
})

const test_addr = new Address('<test@example.com>')

describe('hook_mail', { timeout: 5000 }, () => {
  it('rfc1918', (t, done) => {
    connection = makeConnection({ withTxn: true, ip: '192.168.1.1' })
    connection.set('remote.is_private', true)
    plugin.hook_mail(
      function next() {
        assert.equal(undefined, arguments[0])
        done()
      },
      connection,
      [test_addr],
    )
  })

  it('rfc1918 relaying', (t, done) => {
    connection = makeConnection({
      withTxn: true,
      ip: '192.168.1.1',
      relaying: true,
    })
    connection.set('remote.is_private', true)
    plugin.hook_mail(
      function next() {
        assert.ok([undefined, constants.CONT].includes(arguments[0]))
        done()
      },
      connection,
      [test_addr],
    )
  })

  it('no txn', (t, done) => {
    connection = makeConnection({ ip: '207.85.1.1' })
    plugin.hook_mail(function next() {
      assert.equal(undefined, arguments[0])
      assert.equal(undefined, arguments[1])
      done()
    }, connection)
  })

  it('txn, no helo', (t, done) => {
    plugin.cfg.deny.mfrom_fail = false
    connection = makeConnection({ withTxn: true, ip: '207.85.1.1' })
    plugin.hook_mail(
      function next() {
        assert.equal(undefined, arguments[0])
        assert.equal(undefined, arguments[1])
        done()
      },
      connection,
      [test_addr],
    )
  })

  it('txn', (t, done) => {
    connection = makeConnection({ withTxn: true, ip: '207.85.1.1' })
    connection.set('hello.host', 'mail.example.com')
    plugin.hook_mail(
      function next(rc) {
        assert.equal(undefined, rc)
        done()
      },
      connection,
      [test_addr],
    )
  })

  it('txn, relaying', (t, done) => {
    connection = makeConnection({
      withTxn: true,
      ip: '207.85.1.1',
      relaying: true,
    })
    connection.set('hello.host', 'mail.example.com')
    plugin.hook_mail(
      function next(rc) {
        assert.equal(undefined, rc)
        done()
      },
      connection,
      [test_addr],
    )
  })

  it('txn, relaying, is_private', { timeout: 12000 }, (t, done) => {
    plugin.cfg.relay.context = 'myself'
    plugin.cfg.deny_relay.mfrom_fail = true
    connection = makeConnection({
      withTxn: true,
      ip: '127.0.1.1',
      relaying: true,
    })
    connection.set('remote.is_private', true)
    connection.set('hello.host', 'www.tnpi.net')
    plugin.nu.public_ip = '66.128.51.165'
    plugin.hook_mail(
      function next(rc) {
        assert.equal(undefined, rc)
        done()
      },
      connection,
      [new Address('<nonexist@tnpi.net>')],
    )
  })
})

describe('Authentication-Results', () => {
  let fragments

  beforeEach(() => {
    plugin.cfg.deny.mfrom_fail = false
    plugin.cfg.deny.helo_fail = false
    const configure = plugin._configure_spf.bind(plugin)
    plugin._configure_spf = (spf, conn) => {
      spf.resolver = {
        resolveTxt: () => Promise.reject({ code: 'ENOTFOUND' }),
      }
      return configure(spf, conn)
    }
    connection = makeConnection({ withTxn: true, ip: '207.85.1.1' })
    fragments = []
    connection.auth_results = (msg) => fragments.push(msg)
  })

  const run_hook_mail = (addr) =>
    new Promise((resolve) => plugin.hook_mail(resolve, connection, [addr]))

  it('leaves a domain-name smtp.mailfrom bare', async () => {
    await run_hook_mail(new Address('<test@example.com>'))
    assert.deepEqual(fragments, ['spf=none smtp.mailfrom=example.com'])
  })

  it('quotes an address-literal smtp.mailfrom carrying resinfo', async () => {
    await run_hook_mail(new Address('<x@[tag:a;dkim=pass]>'))
    assert.deepEqual(fragments, ['spf=none smtp.mailfrom="[tag:a;dkim=pass]"'])
  })

  it('leaves a domain-name smtp.helo bare', async () => {
    connection.set('hello.host', 'mail.example.com')
    connection.notes.spf_helo = spf.SPF_NONE
    await run_hook_mail(new Address('<>'))
    assert.deepEqual(fragments, ['spf=none smtp.helo=mail.example.com'])
  })

  it('quotes a HELO carrying resinfo', async () => {
    connection.set('hello.host', 'x;dkim=pass;dmarc=pass')
    connection.notes.spf_helo = spf.SPF_NONE
    await run_hook_mail(new Address('<>'))
    assert.deepEqual(fragments, ['spf=none smtp.helo="x;dkim=pass;dmarc=pass"'])
  })
})
