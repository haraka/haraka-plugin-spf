// node.js built-in modules
const assert = require('node:assert')
const { describe, it, beforeEach } = require('node:test')

// npm modules
const { Address } = require('@haraka/email-address')
const constants = require('haraka-constants')
const fixtures = require('haraka-test-fixtures')

const SPF = require('../lib/spf').SPF
const spf = new SPF()

let plugin
let connection

beforeEach(() => {
  plugin = new fixtures.plugin('spf')

  plugin.timeout = 8000
  plugin.load_spf_ini()

  // comment this line to see detailed SPF evaluation
  plugin.SPF.prototype.log_debug = () => {}

  connection = fixtures.connection.createConnection()
  connection.init_transaction()
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
    connection.remote.ip = '190.168.1.1'
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
    connection.set('remote.ip', '192.0.2.0')
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
    connection.set('remote.is_private', true)
    connection.set('remote.ip', '192.168.1.1')
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
    connection.set('remote.is_private', true)
    connection.set('remote.ip', '192.168.1.1')
    connection.relaying = true
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
    connection.remote.ip = '207.85.1.1'
    delete connection.transaction
    plugin.hook_mail(function next() {
      assert.equal(undefined, arguments[0])
      assert.equal(undefined, arguments[1])
      done()
    }, connection)
  })

  it('txn, no helo', (t, done) => {
    plugin.cfg.deny.mfrom_fail = false
    connection.set('remote.ip', '207.85.1.1')
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
    connection.set('remote.ip', '207.85.1.1')
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
    connection.set('remote.ip', '207.85.1.1')
    connection.set('relaying', true)
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
    connection.set('remote.ip', '127.0.1.1')
    connection.set('remote.is_private', true)
    connection.relaying = true
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
