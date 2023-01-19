
// node.js built-in modules
const assert   = require('assert')

// npm modules
const Address      = require('address-rfc2821').Address;
const constants    = require('haraka-constants');
const fixtures     = require('haraka-test-fixtures')

const SPF = require('../lib/spf').SPF;
const spf = new SPF();

beforeEach(function () {
  this.plugin = new fixtures.plugin('spf')

  this.plugin.timeout = 8000;
  this.plugin.load_spf_ini();

  // uncomment this line to see detailed SPF evaluation
  this.plugin.SPF.prototype.log_debug = () => {};

  this.connection = fixtures.connection.createConnection();
  this.connection.transaction = fixtures.transaction.createTransaction();
})

describe('spf', function () {
  it('loads', function () {
    assert.ok(this.plugin)
  })
})

describe('load_spf_ini', function () {
  it('loads spf.ini from config/spf.ini', function () {
    this.plugin.load_spf_ini()
    assert.ok(this.plugin.cfg.main)
  })
})

describe('return_results', function () {
  it('result, none, reject=false', function (done) {
    this.plugin.cfg.deny.mfrom_none=false;
    this.plugin.return_results(function next () {
      assert.equal(undefined, arguments[0]);
      done()
    }, this.connection, spf, 'mfrom', spf.SPF_NONE, 'test@example.com');
  })

  it('result, none, reject=true', function (done) {

    this.plugin.cfg.deny.mfrom_none=true;
    this.plugin.return_results(function next () {
      assert.equal(DENY, arguments[0]);
      done()
    }, this.connection, spf, 'mfrom', spf.SPF_NONE, 'test@example.com');
  })

  it('result, neutral', function (done) {
    this.plugin.return_results(function next () {
      assert.equal(undefined, arguments[0]);
      done()
    }, this.connection, spf, 'mfrom', spf.SPF_NEUTRAL, 'test@example.com');
  })

  it('result, pass', function (done) {
    this.plugin.return_results(function next () {
      assert.equal(undefined, arguments[0]);
      done()
    }, this.connection, spf, 'mfrom', spf.SPF_PASS, 'test@example.com');
  })

  it('result, softfail, reject=false', function (done) {
    this.plugin.cfg.deny.mfrom_softfail=false;
    this.plugin.return_results(function next () {
      assert.equal(undefined, arguments[0]);
      done()
    }, this.connection, spf, 'mfrom', spf.SPF_SOFTFAIL, 'test@example.com');
  })

  it('result, softfail, reject=true', function (done) {
    this.plugin.cfg.deny.mfrom_softfail=true;
    this.plugin.return_results(function next () {
      assert.equal(DENY, arguments[0]);
      done()
    }, this.connection, spf, 'mfrom', spf.SPF_SOFTFAIL, 'test@example.com');
  })

  it('result, fail, reject=false', function (done) {
    this.plugin.cfg.deny.mfrom_fail=false;
    this.plugin.return_results(function next () {
      assert.equal(undefined, arguments[0]);
      done()
    }, this.connection, spf, 'mfrom', spf.SPF_FAIL, 'test@example.com');
  })

  it('result, fail, reject=true', function (done) {
    this.plugin.cfg.deny.mfrom_fail=true;
    this.plugin.return_results(function next () {
      assert.equal(DENY, arguments[0]);
      done()
    }, this.connection, spf, 'mfrom', spf.SPF_FAIL, 'test@example.com');
  })

  it('result, temperror, reject=false', function (done) {
    this.plugin.cfg.defer.mfrom_temperror=false;
    this.plugin.return_results(function next () {
      assert.equal(undefined, arguments[0]);
      done()
    }, this.connection, spf, 'mfrom', spf.SPF_TEMPERROR, 'test@example.com');
  })

  it('result, temperror, reject=true', function (done) {
    this.plugin.cfg.defer.mfrom_temperror=true;
    this.plugin.return_results(function next () {
      assert.equal(DENYSOFT, arguments[0]);
      done()
    }, this.connection, spf, 'mfrom', spf.SPF_TEMPERROR, 'test@example.com');
  })

  it('result, permerror, reject=false', function (done) {
    this.plugin.cfg.deny.mfrom_permerror=false;
    this.plugin.return_results(function next () {
      assert.equal(undefined, arguments[0]);
      done()
    }, this.connection, spf, 'mfrom', spf.SPF_PERMERROR, 'test@example.com');
  })

  it('result, permerror, reject=true', function (done) {
    this.plugin.cfg.deny.mfrom_permerror=true;
    this.plugin.return_results(    function next () {
      assert.equal(DENY, arguments[0]);
      done()
    }, this.connection, spf, 'mfrom', spf.SPF_PERMERROR, 'test@example.com');
  })

  it('result, unknown', function (done) {
    this.plugin.return_results(function next () {
      assert.equal(undefined, arguments[0]);
      done()
    }, this.connection, spf, 'mfrom', 'unknown', 'test@example.com');
  })
})

describe('hook_helo', function () {
  it('rfc1918', function (done) {
    let completed = 0;
    function next (rc) {
      completed++;
      assert.equal(undefined, rc);
      if (completed >= 2) done()
    }
    this.connection.remote.is_private=true;
    this.plugin.helo_spf(next, this.connection);
    this.plugin.helo_spf(next, this.connection, 'helo.sender.com');
  })

  it('IPv4 literal', function (done) {
    this.connection.remote.ip='190.168.1.1';
    this.plugin.helo_spf(function next (rc) {
      assert.equal(undefined, rc);
      done()
    }, this.connection, '[190.168.1.1]' );
  })
})

const test_addr = new Address('<test@example.com>');

describe('hook_mail', function () {
  it('rfc1918', function (done) {

    this.connection.remote.is_private=true;
    this.connection.remote.ip='192.168.1.1';
    this.plugin.hook_mail(function next () {
      assert.equal(undefined, arguments[0]);
      done()
    }, this.connection, [test_addr]);
  })

  it('rfc1918 relaying', function (done) {
    this.connection.set('remote.is_private', true);
    this.connection.set('remote.ip','192.168.1.1');
    this.connection.relaying=true;
    this.plugin.hook_mail(function next () {
      assert.ok([undefined, constants.CONT].includes(arguments[0]));
      done()
    }, this.connection, [test_addr]);
  })

  it('no txn', function (done) {
    this.connection.remote.ip='207.85.1.1';
    delete this.connection.transaction;
    this.plugin.hook_mail(function next () {
      assert.equal(undefined, arguments[0]);
      done()
    }, this.connection);
  })

  it('txn, no helo', function (done) {
    this.plugin.cfg.deny.mfrom_fail = false;
    this.connection.remote.ip='207.85.1.1';
    this.plugin.hook_mail(function next () {
      assert.equal(undefined, arguments[0]);
      done()
    }, this.connection, [test_addr]);
  })

  it('txn', function (done) {
    this.connection.set('remote', 'ip', '207.85.1.1');
    this.connection.set('hello', 'host', 'mail.example.com');
    this.plugin.hook_mail(function next (rc) {
      assert.equal(undefined, rc);
      done()
    }, this.connection, [test_addr]);
  })

  it('txn, relaying', function (done) {
    this.connection.set('remote.ip', '207.85.1.1');
    this.connection.relaying=true;
    this.connection.set('hello.host', 'mail.example.com');
    this.plugin.hook_mail(function next (rc) {
      assert.equal(undefined, rc);
      done()
    }, this.connection, [test_addr]);
  })

  it('txn, relaying, is_private', function (done) {
    this.timeout(6000)
    this.plugin.cfg.relay.context='myself';
    this.plugin.cfg.deny_relay.mfrom_fail = true;
    this.connection.set('remote.ip', '127.0.1.1');
    this.connection.set('remote.is_private', true);
    this.connection.relaying = true;
    this.connection.set('hello.host', 'www.tnpi.net');
    this.plugin.nu.public_ip = '66.128.51.165';
    this.plugin.hook_mail(function next (rc) {
      assert.equal(undefined, rc);
      done()
    }, this.connection, [new Address('<nonexist@tnpi.net>')]);
  })
})
