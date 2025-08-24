// spf

const SPF = require('./lib/spf').SPF
const net_utils = require('haraka-net-utils')
const DSN = require('haraka-dsn')

exports.SPF = SPF

exports.register = function () {
  // Override logging in SPF module
  SPF.prototype.log_debug = (str) => this.logdebug(str)

  this.load_spf_ini()

  this.register_hook('helo', 'helo_spf')
  this.register_hook('ehlo', 'helo_spf')
}

exports.load_spf_ini = function () {
  this.nu = net_utils // so tests can set public_ip
  this.SPF = SPF

  this.cfg = this.config.get(
    'spf.ini',
    {
      booleans: [
        '-defer.helo_temperror',
        '-defer.mfrom_temperror',

        '-defer_relay.helo_temperror',
        '-defer_relay.mfrom_temperror',

        '-deny.helo_none',
        '-deny.helo_softfail',
        '-deny.helo_fail',
        '-deny.helo_permerror',
        '-deny.mfrom_none',
        '-deny.mfrom_softfail',
        '-deny.mfrom_fail',
        '-deny.mfrom_permerror',
        '-deny.openspf_text',

        '-deny_relay.helo_none',
        '-deny_relay.helo_softfail',
        '-deny_relay.helo_fail',
        '-deny_relay.helo_permerror',
        '-deny_relay.mfrom_none',
        '-deny_relay.mfrom_softfail',
        '-deny_relay.mfrom_fail',
        '-deny_relay.mfrom_permerror',
        '-deny_relay.openspf_text',

        '-skip.relaying',
        '-skip.auth',
      ],
    },
    () => this.load_spf_ini(),
  )

  if (!this.cfg.relay) this.cfg.relay = { context: 'sender' }
  this.cfg.lookup_timeout = this.cfg.main.lookup_timeout || this.timeout - 1
}

exports.helo_spf = async function (next, connection, helo) {
  // bypass auth'ed or relay'ing hosts
  const skip_reason = this.skip_hosts(connection)
  if (skip_reason) {
    connection.results.add(this, { skip: `helo(${skip_reason})` })
    return next()
  }

  if (connection.remote.is_private) {
    connection.results.add(this, { skip: 'helo(private_ip)' })
    return next()
  }

  // RFC 4408, 2.1: "SPF clients must be prepared for the "HELO"
  //           identity to be malformed or an IP address literal.
  if (net_utils.is_ip_literal(helo)) {
    connection.results.add(this, { skip: 'helo(ip_literal)' })
    return next()
  }

  // avoid 2nd EHLO evaluation if EHLO host is identical
  const results = connection.results.get(this)
  if (results && results.domain === helo) return next()

  let timeout = false
  const spf = new SPF()
  const timer = setTimeout(() => {
    timeout = true
    connection.loginfo(this, 'timeout')
    next()
  }, this.cfg.lookup_timeout * 1000)
  timer.unref()

  try {
    const result = await spf.check_host(connection.remote.ip, helo, null)
    if (timer) clearTimeout(timer)
    if (timeout) return
    const host = connection.hello.host
    this.log_result(
      connection,
      'helo',
      host,
      `postmaster@${host}`,
      spf.result(result),
    )

    connection.notes.spf_helo = result // used between hooks
    connection.results.add(this, {
      scope: 'helo',
      result: spf.result(result),
      domain: host,
      emit: true,
    })
    if (spf.result(result) === 'Pass')
      connection.results.add(this, { pass: host })
  } catch (err) {
    connection.logerror(this, err)
  }
  next()
}

exports.hook_mail = async function (next, connection, params) {
  const txn = connection?.transaction
  if (!txn) return next()

  const skip_reason = this.skip_hosts(connection)
  if (skip_reason) {
    txn.results.add(this, { skip: `host(${skip_reason})` })
    return next(CONT, `skipped because host(${skip_reason})`)
  }

  if (connection.remote?.is_private) {
    if (!connection.relaying) return next()
    if (this.cfg.relay?.context !== 'myself') {
      txn.results.add(this, { skip: 'host(private_ip)' })
      return next(CONT, 'envelope from private IP space')
    }
  }

  const mfrom = params[0].address()
  const host = params[0].host
  let spf = new SPF()
  let auth_result

  if (connection.notes?.spf_helo) {
    const h_result = connection.notes.spf_helo
    const h_host = connection.hello?.host
    this.save_to_header(connection, spf, h_result, mfrom, h_host, 'helo')

    if (!host) {
      // Use results from HELO if the return-path is null
      auth_result = spf.result(h_result).toLowerCase()
      connection.auth_results(`spf=${auth_result} smtp.helo=${h_host}`)

      const sender = `<> via ${h_host}`
      return this.return_results(
        next,
        connection,
        spf,
        'helo',
        h_result,
        sender,
      )
    }
  }

  if (!host) return next() // null-sender

  let timeout = false
  const timer = setTimeout(() => {
    timeout = true
    connection.loginfo(this, 'timeout')
    next()
  }, this.cfg.lookup_timeout * 1000)
  timer.unref()

  spf.helo = connection.hello?.host

  const ch_cb = (err, result, ip) => {
    if (timer) clearTimeout(timer)
    if (timeout) return
    if (err) {
      connection.logerror(this, err)
      return next()
    }

    this.log_result(
      connection,
      'mfrom',
      host,
      mfrom,
      spf.result(result),
      ip || connection.remote.ip,
    )
    this.save_to_header(
      connection,
      spf,
      result,
      mfrom,
      host,
      'mailfrom',
      ip || connection.remote.ip,
    )

    auth_result = spf.result(result).toLowerCase()
    connection.auth_results(`spf=${auth_result} smtp.mailfrom=${host}`)

    txn.notes.spf_mail_result = spf.result(result)
    txn.notes.spf_mail_record = spf.spf_record
    txn.results.add(this, {
      scope: 'mfrom',
      result: spf.result(result),
      domain: host,
      emit: true,
    })
    if (spf.result(result) === 'Pass')
      connection.results.add(this, { pass: host })
    this.return_results(next, connection, spf, 'mfrom', result, mfrom)
  }

  try {
    // Always check the client IP first. A relay could be sending inbound mail
    // from a non-local domain, which could case an incorrect SPF Fail result
    // if we check the public IP first. Only check the public IP if the
    // client IP returns a result other than 'Pass'.
    const result = await spf.check_host(connection.remote.ip, host, mfrom)
    // typical inbound (!relay)
    if (!connection.relaying) return ch_cb(null, result)

    // outbound (relaying), context=sender
    if (this.cfg.relay.context === 'sender') return ch_cb(null, result)

    // outbound (relaying), context=myself
    const my_public_ip = await net_utils.get_public_ip()
    const spf_result = result ? spf.result(result).toLowerCase() : undefined
    if (spf_result && spf_result !== 'pass') {
      if (!my_public_ip) return ch_cb(new Error('failed to discover public IP'))
      spf = new SPF()
      const r = await spf.check_host(my_public_ip, host, mfrom)
      return ch_cb(null, r, my_public_ip)
    }
    ch_cb(null, result, connection.remote.ip)
  } catch (err) {
    ch_cb(err)
  }
}

exports.log_result = function (connection, scope, host, mfrom, result, ip) {
  const show_ip = ip || connection.remote.ip
  connection.loginfo(
    this,
    `identity=${scope} ip=${show_ip} domain="${host}" mfrom=<${mfrom}> result=${result}`,
  )
}

exports.return_results = function (
  next,
  connection,
  spf,
  scope,
  result,
  sender,
) {
  const msgpre = scope === 'helo' ? `sender ${sender}` : `sender <${sender}>`
  const deny = connection.relaying ? 'deny_relay' : 'deny'
  const defer = connection.relaying ? 'defer_relay' : 'defer'
  const sender_id = scope === 'helo' ? connection.hello_host : sender
  let text = DSN.sec_unauthorized(
    `http://www.openspf.org/Why?s=${scope}&id=${sender_id}&ip=${connection.remote.ip}`,
  )
  switch (result) {
    case spf.SPF_NONE:
      if (this.cfg[deny][`${scope}_none`]) {
        text = this.cfg[deny].openspf_text
          ? text
          : `${msgpre} SPF record not found`
        return next(DENY, text)
      }
      return next()
    case spf.SPF_NEUTRAL:
    case spf.SPF_PASS:
      return next()
    case spf.SPF_SOFTFAIL:
      if (this.cfg[deny][`${scope}_softfail`]) {
        text = this.cfg[deny].openspf_text ? text : `${msgpre} SPF SoftFail`
        return next(DENY, text)
      }
      return next()
    case spf.SPF_FAIL:
      if (this.cfg[deny][`${scope}_fail`]) {
        text = this.cfg[deny].openspf_text ? text : `${msgpre} SPF Fail`
        return next(DENY, text)
      }
      return next()
    case spf.SPF_TEMPERROR:
      if (this.cfg[defer][`${scope}_temperror`]) {
        return next(DENYSOFT, `${msgpre} SPF Temporary Error`)
      }
      return next()
    case spf.SPF_PERMERROR:
      if (this.cfg[deny][`${scope}_permerror`]) {
        return next(DENY, `${msgpre} SPF Permanent Error`)
      }
      return next()
    default:
      connection.logerror(this, `unknown result code=${result}`)
      return next()
  }
}

exports.save_to_header = (connection, spf, result, mfrom, host, id, ip) => {
  if (!connection?.transaction) return

  const des = result === spf.SPF_PASS ? 'designates' : 'does not designate'
  const identity = `identity=${id}; client-ip=${ip || connection.remote.ip}`
  connection.transaction.add_leading_header(
    'Received-SPF',
    `${spf.result(result)} (${connection.local.host}: domain of ${host} ${des} ${connection.remote.ip} as permitted sender) receiver=${connection.local.host}; ${identity} helo=${connection.hello.host}; envelope-from=<${mfrom}>`,
  )
}

exports.skip_hosts = function (connection) {
  const skip = this?.cfg?.skip
  if (skip) {
    if (skip.relaying && connection.relaying) return 'relay'
    if (skip.auth && connection.notes.auth_user) return 'auth'
  }
}
