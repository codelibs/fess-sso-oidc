OpenID Connect SSO Plugin for Fess
[![Java CI with Maven](https://github.com/codelibs/fess-sso-oidc/actions/workflows/maven.yml/badge.svg)](https://github.com/codelibs/fess-sso-oidc/actions/workflows/maven.yml)
==================================

OpenID Connect single sign-on for [Fess](https://github.com/codelibs/fess).

This plugin provides the **SSO authenticator** behind `sso.type=oic`: Fess acts as a relying
party, sends the browser to the OpenID provider's authorization endpoint, exchanges the
authorization code for an ID token on the back channel, and reads the user's identity and groups
out of the ID token's claim set.

> **The plugin is called `oidc`, the setting is `oic`.** The repository, the jar and the
> documentation say OIDC, because that is what the protocol is called. The configuration value and
> the component name are `oic`, an older internal abbreviation, and every configuration key is
> `oic.*`. `SsoManager` maps no alias between the two spellings, so **`sso.type=oidc` selects
> nothing** and SSO stays off. Write `sso.type=oic`.

It was part of the Fess distribution until 15.9.

**Installing this plugin does not make a Fess installation any smaller.** Unlike the other
`fess-sso-*` plugins, this one bundles no third-party library: everything the authenticator
compiles against stays in the war either way — `google-oauth-client` is a direct dependency of
Fess, `google-http-client` and `google-http-client-gson` are shared with the Google API client that
Fess keeps to supply `fess-ds-gsuite`, and Guava is used across Fess itself. The jar is 17 KB: two
classes, the nested user class, the synthetic switch-map class, and the DI file. The split buys
maintenance only: this authenticator can be released, fixed and ruled out of a problem on its own.

## Installation

```
$ bin/fess-setup install plugin fess-sso-oidc
```

Or download the jar from [maven.codelibs.org](https://maven.codelibs.org/org/codelibs/fess/fess-sso-oidc/)
and put it in `app/WEB-INF/plugin`. Restart Fess afterwards: the components this plugin
contributes are read when the DI container is built.

## Configuration

Set these on the General page of the administration screen, or write them to
`app/WEB-INF/conf/system.properties`. None of these are `fess_config.properties` keys.

First select this authenticator:

| Key | Value |
| --- | --- |
| `sso.type` | `oic` (not `oidc`) |

Then configure the client registered with the OpenID provider:

| Key | Value |
| --- | --- |
| `oic.auth.server.url` | the authorization endpoint (default `https://accounts.google.com/o/oauth2/auth`) |
| `oic.token.server.url` | the token endpoint (default `https://accounts.google.com/o/oauth2/token`) |
| `oic.client.id` | the client ID |
| `oic.client.secret` | the client secret |
| `oic.issuer` | the issuer identifier the ID token's `iss` claim has to equal; optional, see below. `system.properties` only: the administration screen has no field for it |
| `oic.scope` | the requested scopes, space-separated; the provider needs `openid` and Fess needs `email` |
| `oic.redirect.url` | the redirect URI; `{oic.base.url}/sso/` is used when the key is absent |
| `oic.base.url` | the Fess base URL the redirect URI is built from (default `http://localhost:8080`) |
| `oic.default.groups` | groups applied to every user whose ID token carries no `groups` claim, comma-separated |
| `oic.default.roles` | roles applied to every user, comma-separated |

Both endpoint URLs, and the value for `oic.issuer` (the document's `issuer`, copied exactly), can be
read from the provider's `/.well-known/openid-configuration`.

A `-Dfess.system.<key>=...` on the JVM command line reaches `oic.default.groups` and
`oic.default.roles` only, and there only for a key `system.properties` does not hold. The other
eight are read straight from the `systemProperties` component, which never consults JVM system
properties: for those, the file or the administration screen is the only channel.

Five things are worth knowing before the first login:

* **The user id is the `email` claim.** An ID token without one is refused with a warning naming
  `oic.scope`, and no session is created — so `email` has to be among the scopes the provider
  grants, and the account has to have an address. The user id is also what a document ACL has to
  name for role-based search to match.
* **Groups come from the `groups` claim, verbatim.** There is no directory lookup and no expansion
  of nested groups, so which groups arrive is entirely up to the provider's claim configuration; a
  provider that emits full paths sends `/parent/child`, which does not match a document tagged with
  the plain name. A claim that is absent falls back to `oic.default.groups`; a claim that is present
  but empty does not, and leaves the user with no groups. Roles are always `oic.default.roles`:
  no claim is read for them.
* **An empty `oic.redirect.url` is not an absent one.** The fallback to `{oic.base.url}/sso/`
  applies only when the key is missing. Saving the General page writes the field even when it is
  blank, and the authorization request then carries a valueless `redirect_uri` parameter. Either
  fill the field in or remove the key from `system.properties`.
* **The ID token's signature is deliberately not verified; TLS to the token endpoint is the trust
  anchor.** The token is read from the token endpoint over the back channel and never from the
  browser, and [OpenID Connect Core 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
  (item 6) lets the TLS server validation of that exchange stand in for the signature. For that
  reason `oic.token.server.url` has to be `https`; `http` is accepted only for `localhost`,
  `127.x.x.x` and `::1`, compared as written with no name lookup, and any other value makes every
  login fail with a warning in the log. The claims are checked as follows:
  * `aud` has to be the string `oic.client.id` or an array that contains it, and `azp`, when the
    token carries one, has to equal it (a token with several audiences must carry it). A blank
    `oic.client.id` refuses every token.
  * `exp` is required and has to be a number. A token is accepted while the current time is less
    than `exp` plus 300 seconds of clock skew; the warning for an expired token names `exp`, the
    current time and the skew, so a host with a wrong clock can be recognised.
  * `iss` is compared with `oic.issuer`, exactly (no normalisation of a trailing slash or the
    scheme), only when that key is set. When it is not, the check is skipped and one warning per
    start says so. Setting it is recommended.
  * `nonce` and PKCE are not implemented, and `iat` and `nbf` are not checked.
* **There is no single logout and no metadata endpoint.** This authenticator implements neither, so
  `/sso/logout` and `/sso/metadata` answer 400 and logging out ends the Fess session only.

See the [OpenID Connect SSO documentation](https://fess.codelibs.org/stable/config/sso-oidc.html)
for the provider side of the registration.

## Version

| Fess | Plugin |
| --- | --- |
| 15.9.x | 15.9.x |

Match the minor version. Installing this plugin into Fess 15.8 or earlier breaks SSO with a 500:
those versions register `oicAuthenticator` in their own `fess_sso++.xml`, and a second
registration under the same name from this plugin makes `getComponent()` fail with
`TooManyRegistrationComponentException`.

## How it plugs in

Nothing here is wired by class name from Fess. The plugin ships one additive LastaDi file that
Fess merges from every jar on the class path:

* `fess_sso++.xml` registers `oicAuthenticator`. `SsoManager.getAuthenticator()` resolves an
  authenticator as `<sso.type>Authenticator`, so the component name is what makes `sso.type=oic`
  resolve — and what makes `sso.type=oidc` resolve to nothing. It is a singleton, because the
  authenticator registers that instance with `ssoManager` from its `init()`.

The `SsoAuthenticator` interface, `SsoManager`, `SsoAction` and the SSO section of the
administration screen remain in Fess. Only the authenticator and the credential it hands to
`FessLoginAssist` ship here; the libraries they compile against are supplied by the war, so this
jar shades nothing.
