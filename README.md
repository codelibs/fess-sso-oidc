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
| `oic.jwks.uri` | the provider's `jwks_uri`; setting it turns on back-channel logout, see below. Optional. `system.properties` only: the administration screen has no field for it |
| `oic.pkce` | `false` turns PKCE off; any other value, and an absent key, leave it on. Optional, see below. `system.properties` only: the administration screen has no field for it |
| `oic.scope` | the requested scopes, space-separated; the provider needs `openid` and Fess needs `email` |
| `oic.redirect.url` | the redirect URI; `{oic.base.url}/sso/` is used when the key is absent |
| `oic.base.url` | the Fess base URL the redirect URI is built from (default `http://localhost:8080`) |
| `oic.default.groups` | groups applied to every user whose ID token carries no `groups` claim, comma-separated |
| `oic.default.roles` | roles applied to every user, comma-separated |

Both endpoint URLs, and the value for `oic.issuer` (the document's `issuer`, copied exactly), can be
read from the provider's `/.well-known/openid-configuration`.

A `-Dfess.system.<key>=...` on the JVM command line reaches `oic.default.groups` and
`oic.default.roles` only, and there only for a key `system.properties` does not hold. The other
nine are read straight from the `systemProperties` component, which never consults JVM system
properties: for those, the file or the administration screen is the only channel.

Six things are worth knowing before the first login:

* **The user id is the `email` claim.** An ID token without one, or whose `email` is not a string,
  is refused with a warning naming `oic.scope`, and no session is created — so `email` has to be
  among the scopes the provider grants, and the account has to have an address. The address is used
  exactly as the provider sent it, so one that contains a control character (a line break, a TAB,
  `U+0085`, and the like, or `U+2028` / `U+2029`) is refused as well, with a warning that names
  the character and its position and not the value. The user id is also what a document ACL has to
  name for role-based search to match.
* **Groups come from the `groups` claim, verbatim.** There is no directory lookup and no expansion
  of nested groups, so which groups arrive is entirely up to the provider's claim configuration; a
  provider that emits full paths sends `/parent/child`, which does not match a document tagged with
  the plain name. A claim that is absent falls back to `oic.default.groups`; a claim that is present
  but empty does not, and leaves the user with no groups. Roles are always `oic.default.roles`:
  no claim is read for them.
* **An empty `oic.redirect.url` is not an absent one.** The fallback to `{oic.base.url}/sso/`
  applies only when the key is missing. A `oic.redirect.url=` line in `system.properties` makes the
  authorization request carry a valueless `redirect_uri` parameter, so either give it a value or
  remove the line. A blank field on the General page is safe: saving it removes the key, and the
  fallback applies.
* **The ID token's signature is deliberately not verified; TLS to the token endpoint is the trust
  anchor.** The token is read from the token endpoint over the back channel and never from the
  browser, and [OpenID Connect Core 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
  (item 6) lets the TLS server validation of that exchange stand in for the signature. For that
  reason `oic.token.server.url` has to be `https`; `http` is accepted only for `localhost`,
  `127.x.x.x` and `::1`, compared as written with no name lookup, and any other value makes every
  login fail with a warning in the log. So does a `#fragment` in the URL, which the token request
  cannot carry. The claims are checked as follows:
  * `aud` has to be the string `oic.client.id` or an array that contains it, and `azp`, when the
    token carries one, has to equal it (a token with several audiences must carry it). A blank
    `oic.client.id` refuses every token.
  * `exp` is required and has to be a number. A token is accepted while the current time is less
    than `exp` plus 300 seconds of clock skew; the warning for an expired token names `exp`, the
    current time and the skew, so a host with a wrong clock can be recognised.
  * `iss` is compared with `oic.issuer`, exactly (no normalisation of a trailing slash or the
    scheme), only when that key is set. When it is not, the check is skipped and one warning per
    start says so. Setting it is recommended.
  * `nonce`: every authorization request carries a fresh random `nonce`, kept in the session next
    to the `state` and discarded when the callback arrives. The ID token has to contain a string
    `nonce` claim equal to it; a token without the claim, or with another value, is refused with a
    warning that does not repeat either value. A provider that omits the claim therefore cannot be
    used (OpenID Connect Core requires it to echo the nonce), and there is no setting to relax this.
    A login that was started before the plugin was updated fails once and has to be retried.
  * `iat` and `nbf` are not checked.
* **PKCE (RFC 7636) is on.** Every authorization request carries a `code_challenge` with
  `code_challenge_method=S256`, derived from a random `code_verifier` that stays in the session
  next to the `state` and `nonce`; the token request sends the verifier, and the provider refuses
  the code without it. A provider that requires PKCE for the client therefore works. One that
  supports PKCE without requiring it enforces the verifier once a challenge is sent, which this
  plugin always does, and one that does not support it ignores the parameters. Only a provider that
  rejects the unknown `code_challenge` parameter needs `oic.pkce=false`, which sends neither parameter. The setting is read for each
  login, so it takes effect without a restart. A login that was started without a challenge (PKCE
  off, or a node that predates it) is completed without a verifier; one that was started with a
  challenge fails if a node without PKCE completes it, so update every node before a login relies
  on it.
* **There is no single logout of the user's own and no metadata endpoint.** `/sso/metadata` and a `/sso/logout`
  that is not a back-channel logout request answer 400, and logging out ends the Fess session only. The one
  request `/sso/logout` takes is the provider's, see [Back-channel logout](#back-channel-logout).
* **An ID token's validity does not limit the session.** Without back-channel logout the Fess session lasts until the
  user logs out or the session expires from inactivity, whatever happens to the login at the provider.

## Back-channel logout

With [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) the provider
tells Fess, server to server, that a login has ended, and Fess ends the session of that login. Without it a session
outlives the login at the provider.

It is on when `oic.jwks.uri` is set and nothing else needs switching: a provider that does not send logout tokens
does no harm, and without the setting every logout request is answered 400. `oic.issuer` and `oic.client.id` have to be
set too, because they are what the token is checked against. Copy `jwks_uri` and `issuer` from the provider's
`/.well-known/openid-configuration`, where `backchannel_logout_supported` says whether the provider can do it. The
endpoint is the existing `{Fess base URL}/sso/logout`; no other setting is added.

At the provider, register `{Fess base URL}/sso/logout` as the client's *back-channel logout URL*, and, where the provider
has the option (`backchannel_logout_session_required`), have it send the session id: the provider then ends one
session and not every session of the user. The ID token has to carry the same `sid`, which Fess keeps with the login.

* **The token is verified**, unlike the ID token: its signature (RS256, RS384, RS512, ES256, ES384 or ES512, with a key of
  the `jwks_uri` document, which has to be `https`, or `http` on the loopback address like the token endpoint), `iss`
  (`oic.issuer`), `aud` (`oic.client.id`), `iat` and `exp` (the same 300 seconds of clock skew as for the ID token; a token
  issued more than an hour ago is refused whatever its `exp`), `jti`, the `events` member
  `http://schemas.openid.net/event/backchannel-logout`, no `nonce`, and `sid` or `sub`. A token is accepted once:
  a `jti` that was used is refused on every node.
* **The answer is `200` when the logout was recorded and `400` otherwise**, with `Cache-Control: no-store`. A request that
  is not a `POST` with a `logout_token` form parameter is not back-channel logout and gets the answer it always had. The first refusal of each kind
  is logged as a warning that names the failed check, and the later ones at debug level, because the endpoint is anonymous; no
  token, `sid` or `sub` is logged. If the logout cannot be recorded
  the answer is `400` and the same token can be sent again.
* **A session ends when it is next used.** Fess records the logout in the coordinator index of the search engine
  (`fess_config.coordinator`), where every node reads it, so it works with in-memory sessions and with
  `FESS_SESSION_STORE=opensearch` alike. The node that received the request ends the session at once; another node
  looks at most every 30 seconds, so a session ends there within 30 seconds of the request that follows. The session ends the
  way a SAML session ends at its `SessionNotOnOrAfter`: locally, with no logout sent back to the provider, and recorded with
  the other ended sessions in the audit log by Fess versions that record them.
* **What is ended.** With `sid` in the token, the login that has that `sid`. With `sub` only, every login of that subject
  opened before the request. A login made before this plugin version, or whose ID token had no `sid` when a `sid`
  was sent, cannot be found and is not ended.
* **If the coordinator index cannot be read, no session is ended** (one warning is logged): a failing index is not read as a
  logout. The time of a login is compared with the time the logout was received, possibly by another node, so the nodes
  should keep their clocks in step.
* **Not covered:** encrypted logout tokens (JWE), the Entra ID and SPNEGO authenticators, and front-channel logout.

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

When Fess keeps its HTTP sessions in OpenSearch (`FESS_SESSION_STORE=opensearch`), `init()` also
registers the logged-in user with the session store, so a login started on one node can end on
another and the user stays logged in on all of them. Only the user name, groups and roles are
stored, with the issuer, subject and session id of the ID token and the time of the login that back-channel logout finds it by; no token of the login is. Run the same plugins on every node: the stored format depends on
the registered classes, and a node with a different set does not read the sessions of the others.
This needs the plugin 15.10 on every node. Adding or removing an SSO plugin changes that set, so it
invalidates the stored sessions: users log in again.
A login has to be completed within 10 minutes of its authorization request.

The `SsoAuthenticator` interface, `SsoManager`, `SsoAction` and the SSO section of the
administration screen remain in Fess. Only the authenticator and the credential it hands to
`FessLoginAssist` ship here; the libraries they compile against are supplied by the war, so this
jar shades nothing.
