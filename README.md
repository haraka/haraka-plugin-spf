[![CI Test Status][ci-img]][ci-url]
[![Code Climate][clim-img]][clim-url]

# haraka-plugin-spf

This plugin implements the Sender Policy Framework (SPF). See the [Wikipedia article on SPF](http://en.wikipedia.org/wiki/Sender_Policy_Framework) and [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) for details.

By default this plugin only adds Received-SPF headers to a message. There are options to reject mail that fails SPF. `[deny]helo_fail` and `[deny]mfrom_fail` are the closest match for the intent of SPF but that requires whitelisting hosts that forward mail from another domain whilst preserving the original return-path.

## Configuration

### spf.ini default settings

```ini
; The lookup timeout, in seconds. Setting it lower is better.
lookup_timeout = 29


[relay]
context=sender


[skip]
relaying=false
auth=false


[defer]
helo_temperror=false
mfrom_temperror=false


[deny]
helo_none=false
helo_softfail=false
helo_fail=false
helo_permerror=false

mfrom_none=false
mfrom_softfail=false
mfrom_fail=false
mfrom_permerror=false

openspf_text=false


; SPF settings used when connection.relaying=true
[defer_relay]
helo_temperror=false
mfrom_temperror=false


[deny_relay]
helo_none=false
helo_softfail=false
helo_fail=false
helo_permerror=false

mfrom_none=false
mfrom_softfail=false
mfrom_fail=false
mfrom_permerror=false

openspf_text=false

[skip]
; bypass hosts that match these conditions

; hosts that relay through us
relaying = false

; hosts that are SMTP AUTH'ed
auth = false
```

### relay.context

On connections with relaying privileges (MSA or mail relay), it is often desirable to evaluate SPF from the context of Haraka's public IP(s), in the same fashion the next mail server will evaluate it when we send to them. In that use case, Haraka should use `relay.context=myself`.

    * context=sender    evaluate SPF based on the sender (connection.remote.ip)
    * context=myself    evaluate SPF based on Haraka's public IP

The rest of the optional settings (disabled by default) permit deferring or
denying mail from senders whose SPF fails the checks.

### openspf_text

There's a special setting that would allow the plugin to emit a funny explanation text on SPF DENY, essentially meant to be visible to end-users that receive the bounce. The text is `http://www.openspf.org/Why?s=${scope}&id=${sender_id}&ip=${connection.remote.ip}` and is enabled by:

```ini
[deny]
openspf_text = true

; in case you DENY on failing SPF on hosts that are relaying (but why?)
[deny_relay]
openspf_text = true
```

### Things to Know

- Most senders do not publish SPF records for their mail server _hostname_,
  which means that the SPF HELO test rarely passes. During observation in 2014,
  more spam senders have valid SPF HELO than ham senders. If you expect very
  little from SPF HELO validation, you might still be disappointed.

- Enabling error deferrals will cause excessive delays and perhaps bounced
  mail for senders with broken DNS. Enable this only if you are willing to
  delay and sometimes lose valid mail.

- Broken SPF records by valid senders are common. Keep that in mind when
  considering denial of SPF error results. If you deny on error, budget
  time for instructing senders on how to correct their SPF records so they
  can email you.

- The only deny option most sites should consider is `mfrom_fail`. That will
  reject messages that explicitely fail SPF tests. SPF failures have a high
  correlation with spam. However, up to 10% of ham transits forwarders and/or
  email lists which frequently break SPF. SPF results are best used as inputs
  to other plugins such as DMARC, [spamassassin](https://haraka.github.io/plugins/spamassassin), and [karma](http://haraka.github.io/plugins/karma).

- Heed well the implications of SPF, as described in [RFC 4408](http://tools.ietf.org/html/rfc4408#section-9.3)

## Testing

This plugin provides a command-line tool to debug SPF issues or check results.

To check the SPF record for a domain:

```sh
# spf --ip 1.2.3.4 --domain fsl.com
ip=1.2.3.4 helo="" domain="fsl.com" result=Fail
```

To check the SPF record for a HELO/EHLO name:

```sh
# spf --ip 1.2.3.4 --helo foo.bar.com
ip=1.2.3.4 helo="foo.bar.com" domain="" result=None
```

You can add `--debug` to the option arguments to see a full trace of the SPF processing.

### SPF Resource Record Type

Node does not support the SPF DNS Resource Record type. Only TXT records are checked. This is a non-issue as < 1% (as of 2014) of SPF records use the SPF RR type. Due to lack of adoption, SPF has deprecated the SPF RR type.

<!-- leave these buried at the bottom of the document -->

[ci-img]: https://github.com/haraka/haraka-plugin-spf/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/haraka/haraka-plugin-spf/actions/workflows/ci.yml
[clim-img]: https://codeclimate.com/github/haraka/haraka-plugin-spf/badges/gpa.svg
[clim-url]: https://codeclimate.com/github/haraka/haraka-plugin-spf
