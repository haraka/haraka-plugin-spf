const assert = require('assert')

const SPF = require('../lib/spf').SPF

SPF.prototype.log_debug = () => {} // noop, hush debug output

beforeEach(function () {
  this.SPF = new SPF()
})

describe('SPF', function () {
  it('new SPF', function () {
    assert.ok(this.SPF)
  })

  it('constants', function () {
    assert.equal(1, this.SPF.SPF_NONE)
    assert.equal(2, this.SPF.SPF_PASS)
    assert.equal(3, this.SPF.SPF_FAIL)
    assert.equal(4, this.SPF.SPF_SOFTFAIL)
    assert.equal(5, this.SPF.SPF_NEUTRAL)
    assert.equal(6, this.SPF.SPF_TEMPERROR)
    assert.equal(7, this.SPF.SPF_PERMERROR)
    assert.equal(10, this.SPF.LIMIT)
  })

  it('mod_redirect, true', async function () {
    this.SPF.been_there['example.com'] = true
    const rc = await this.SPF.mod_redirect('example.com')
    // assert.equal(null, err);
    assert.equal(1, rc)
  })

  it('mod_redirect, false', async function () {
    this.timeout = 4000
    this.SPF.count = 0
    this.SPF.ip = '212.70.129.94'
    this.SPF.mail_from = 'fraud@aexp.com'

    const rc = await this.SPF.mod_redirect('aexp.com')
    switch (rc) {
      case 7:
        // from time to time (this is the third time we've seen it,
        // American Express publishes an invalid SPF record which results
        // in a PERMERROR. Ignore it.
        assert.equal(rc, 7, 'aexp SPF record is broken again')
        break
      case 6:
        assert.equal(rc, 6, 'temporary (likely DNS timeout) error')
        break
      default:
        assert.equal(rc, 3)
    }
  })

  it('resolves more than one IP in mech_mx', async function () {
    this.timeout = 4000
    this.SPF.domain = 'gmail.com'
    this.SPF.ip_ver = 'ipv4'

    await this.SPF.mech_mx()
    assert.equal((this.SPF._found_mx_addrs.length > 1), true)
  })

  it('check_host, gmail.com, fail', async function () {
    this.timeout = 3000
    this.SPF.count = 0
    const rc = await this.SPF.check_host(
      '212.70.129.94',
      'gmail.com',
      'haraka.mail@gmail.com',
    )
    switch (rc) {
      case 1:
        assert.equal(rc, 1, 'none')
        console.log(
          'Why do DNS lookup fail to find gmail SPF record on GitHub Actions?',
        )
        break
      case 3:
        assert.equal(rc, 3, 'fail')
        break
      case 4:
        assert.equal(rc, 4, 'soft fail')
        break
      case 7:
        assert.equal(rc, 7, 'perm error')
        break
      default:
        assert.equal(rc, 4)
    }
  })

  it('check_host, facebook.com, pass', async function () {
    this.timeout = 3000
    this.SPF.count = 0
    const rc = await this.SPF.check_host('69.171.232.145', 'facebookmail.com')
    assert.equal(rc, this.SPF.SPF_PASS, 'pass')
  })

  it('valid_ip, true', function (done) {
    assert.equal(this.SPF.valid_ip(':212.70.129.94'), true)
    done()
  })

  it('valid_ip, false', function (done) {
    assert.equal(this.SPF.valid_ip(':212.70.d.94'), false)
    done()
  })
})
