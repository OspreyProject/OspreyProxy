# Self-hosted updates and version control

This guide is for operators who want to control which version of the Osprey extension runs on which endpoints, rather
than letting the browser update the extension from the public web store on its own schedule. It covers the self-hosted
CRX update server built into `OspreyProxy`, how to point managed browsers at it, and how to stage, pin, and roll back
builds. It builds on `docs/self-hosting.md`, which covers running the proxy itself.

The update server targets Chromium browsers, which are Chrome, Edge, Brave, and Vivaldi. Firefox uses a different update
format and a different signing model, so it is covered separately at the end.

## Why this exists

An MSP is accountable for stability on its clients' machines. By default a browser pulls extension updates from the
public store whenever it decides to, which the MSP does not control. The update server moves that control to the MSP. An
MSP can hold a client on a known-good build, push a new build to a small group first, watch it, then roll it out to
everyone, and reverse a bad update.

## How Chromium self-hosted updates work

A managed browser is force-installed with an extension id and an update URL. On its own polling schedule the browser
fetches that update URL, which returns a small XML manifest naming the version currently on offer and the absolute URL
of the CRX package that carries it. If the offered version is higher than the installed one, the browser downloads and
installs the CRX. Three facts follow from this and shape everything below.

1. The version advertised in the manifest must equal the version inside the packaged CRX, so the server never invents or
   rewrites versions. It serves exactly what you packaged.
2. The browser only ever moves to a higher version. A manifest that offers an equal or lower version is treated as no
   update, which is the fact that makes rollback a republish rather than a downgrade.
3. For a force-installed extension the update URL comes from the browser's force-install policy, not from the
   `update_url` field baked into the extension's own `manifest.json`. The policy is what you point at this server. The
   public build keeps its store `update_url`, and managed endpoints override it through policy.

## Enabling the server

The feature is off by default, so the public deployment serves no updates and none of these endpoints exist. To turn it
on, set the following in `application.properties` or as environment overrides, then create the directory it points at.

```properties
osprey.updates.enabled=true
osprey.updates.path=/var/lib/osprey/updates
osprey.updates.base-url=https://updates.example.com
osprey.updates.app-id=aaaabbbbccccddddeeeeffffgggghhhh
```

The `osprey.updates.base-url` value is the public origin browsers reach this server on, and it is used to build the
absolute CRX URLs in every manifest and feed. Set it in production. Behind Nginx the request the application sees is the
internal one, so leaving `base-url` blank would put internal URLs into your manifests. When it is blank the server falls
back to deriving the origin from the incoming request, which is only correct for direct, unproxied access during local
testing.

The `osprey.updates.app-id` value is the 32-character application id of your packaged extension. Setting it is
recommended so every manifest carries the right id. When it is blank the server echoes back the id the browser presents
in its update check, which also works for a single-extension server but is less explicit.

## The updates directory

`osprey.updates.path` points at a directory that holds two operator-authored files and the packaged CRX builds.

```
/var/lib/osprey/updates/
  releases.json        # every packaged build: version, CRX filename, notes, date
  channels.json        # which version each channel currently offers
  osprey-2.0.6.crx     # the packaged builds themselves, one per release
  osprey-2.0.7.crx
  osprey-2.0.8.crx
```

The directory must be readable by the service user. Keep every CRX you have ever published, because a fast rollback
depends on the previous package still being present.

`releases.json` is append-mostly, because publishing a build adds one entry. `channels.json` is the knob you flip to
stage a beta, pin a client to a known-good build, or roll back. The proxy re-reads both files whenever either one
changes, checked at most once per second, so a change takes effect within about a second with no restart. If a file is
temporarily unreadable or malformed, the server keeps the last good catalog in place rather than dropping to offering
nothing, so a bad edit never removes updates from a fleet in a surprising way.

See `docs/updates.example.releases.json` and `docs/updates.example.channels.json` for the exact formats. In short, a
release is one object with a `version` and a `crx` filename plus optional `date`, `notes`, `min_browser_version`, and
`rollback_of` fields, and a channel maps a name to either an exact version or the literal `latest`.

## Packaging a CRX

The server distributes packages that you build. To package one, load an unpacked build of `OspreyClient/src/main` and
pack it with a private key you keep offline.

```bash
# First build produces both the CRX and a new key. Keep the .pem private and reuse it forever.
chrome --pack-extension=/path/to/OspreyClient/src/main

# Later builds reuse the same key so the extension id stays constant.
chrome --pack-extension=/path/to/OspreyClient/src/main --pack-extension-key=/path/to/osprey.pem
```

The extension id is derived from the public half of that key and stays constant as long as you reuse the key. Read the
id from `chrome://extensions` after a test install, or derive it from the key, and put it in `osprey.updates.app-id`.
The `.pem` private key is the identity of your extension. Keep it offline and backed up, because losing it changes your
extension id and losing control of it lets someone else sign packages under your id.

Rename each packed CRX to match the version inside it, for example `osprey-2.0.6.crx`, and drop it into the updates
directory. The helper script `docs/osprey-release.sh` copies a CRX into the directory and appends a matching entry to
`releases.json` so you do not hand-edit JSON for every build.

## Endpoints

Every endpoint is a plain GET under `/updates/`, so none of them requires a tenant key. Browsers fetching updates cannot
present one, and the multi-segment path is never treated as an extension-facing provider endpoint.

- `GET /updates/{channel}.xml` returns the Chromium update manifest for a channel, for example
  `/updates/stable.xml`. This is the URL you point a force-install policy at. An unknown channel returns 404 so a
  misrouted policy is visible, and a known channel whose build is momentarily missing returns a valid no-update manifest
  so endpoints keep their current version.
- `GET /updates/download/{file}` streams a packaged CRX, for example `/updates/download/osprey-2.0.6.crx`. It serves
  only files that a release in the catalog references.
- `GET /updates/releases.json` returns the machine-readable release feed described below.
- `GET /updates/releases.xml` returns the same feed as RSS 2.0 for subscription in a feed reader.
- `GET /updates/channels.json` returns just the current channel-to-version resolution, which is a convenient view for a
  person or for the hosted console.

## Pointing browsers at the server

For a force-installed extension, the update URL rides in the force-install policy value, which is the extension id and
the update URL joined by a semicolon. Assign a group of endpoints to a channel by giving that group the matching channel
URL. This is how a beta group and a stable group differ.

Chrome and Edge, through Group Policy or Intune, set `ExtensionInstallForcelist`. Each entry is one string.

```
aaaabbbbccccddddeeeeffffgggghhhh;https://updates.example.com/updates/stable.xml
```

Point a beta group at the beta channel instead.

```
aaaabbbbccccddddeeeeffffgggghhhh;https://updates.example.com/updates/beta.xml
```

Brave and Vivaldi are Chromium-based and read the same Chromium managed policy, so the same forcelist entry applies. The
managed storage path differs per browser, which is documented alongside the other deployment templates in
`OspreySite` (the deployment page from the cross-browser deployment work). Preventing a user from removing the extension
is done with the browser's force-install policy itself, not with an Osprey setting, so treat it as a browser-level
control you configure rather than something the extension enforces.

## Channels and staging a beta

A channel is nothing more than a name in `channels.json` with its own manifest URL. Staging an update to a subset of a
client's endpoints is a two-part action. First, point that subset's force-install URL at the beta channel once and leave
it there. Second, set the beta channel to the new version while stable stays where it is.

```json
{
  "channels": {
    "stable": {
      "version": "2.0.6"
    },
    "beta": {
      "version": "2.0.7"
    }
  }
}
```

Beta endpoints move to 2.0.7 on their next poll, while stable endpoints stay on 2.0.6. When the new build has proven
itself on the beta group, promote it to everyone by setting stable to the same version.

```json
{
  "channels": {
    "stable": {
      "version": "2.0.7"
    },
    "beta": {
      "version": "latest"
    }
  }
}
```

A channel set to `latest` always tracks the highest release present, which is convenient for a beta group that should
always test the newest build. A channel pinned to an exact version ignores newer builds until you change the pin, which
is what holds a client steady.

## Version pin

Pinning is just setting a channel to an exact version and leaving it there. That client receives that version and no
other, even after you add newer releases, until you move the pin. Pin a client that needs stability, or a client under a
change freeze, to the exact version it has validated.

## Rollback

Because the browser only ever moves to a higher version, pointing a channel back at an older version does not pull an
already-updated endpoint back down. It only stops endpoints that have not yet taken the bad build from taking it. A real
rollback of endpoints that already updated is published as a new, higher version that contains the previous good code.

The steps to roll a channel back from a bad 2.0.7 to the code of 2.0.6 are as follows.

1. Immediately pin the affected channel back to 2.0.6 in `channels.json`. This stops any endpoint that has not yet
   updated from taking 2.0.7 and limits the blast radius while you prepare the rollback build.
2. Repackage the 2.0.6 build under a higher version, for example 2.0.8, using the same signing key. The code is 2.0.6's
   code and only the version number is raised.
3. Add the 2.0.8 build to `releases.json` with a `rollback_of` value of `2.0.7` so the provenance is clear in the feed,
   and pin the channel to 2.0.8.

Every endpoint, including those that already took 2.0.7, now sees 2.0.8 as a normal higher-version update and moves to
it, which is the code you trust. Keeping every previously packaged CRX on disk is what makes step two fast, because you
repackage from a build you still have.

If you need to force an already-installed bad version to stop running before the rollback build is ready, the
browser-level `ExtensionSettings` policy has a `minimum_version_required` field. Setting it above the bad version
disables the extension on endpoints below that version. This disables rather than downgrades, so use it only as a
stop-gap for a genuinely harmful build, and prefer the rollback republish for normal recovery.

## The release feed

`GET /updates/releases.json` is the feed a change-management process or the hosted console subscribes to. Poll it and
diff it against the last version you saw. Its shape is stable and self-describing.

```json
{
  "appId": "aaaabbbbccccddddeeeeffffgggghhhh",
  "channels": {
    "stable": {
      "pin": "2.0.6",
      "version": "2.0.6",
      "download": "https://updates.example.com/updates/download/osprey-2.0.6.crx",
      "manifest": "https://updates.example.com/updates/stable.xml"
    },
    "beta": {
      "pin": "latest",
      "version": "2.0.8",
      "download": "https://updates.example.com/updates/download/osprey-2.0.8.crx",
      "manifest": "https://updates.example.com/updates/beta.xml"
    }
  },
  "releases": [
    {
      "version": "2.0.8",
      "download": "https://updates.example.com/updates/download/osprey-2.0.8.crx",
      "date": "2026-03-06T00:00:00Z",
      "notes": "Rollback: republishes the 2.0.6 build under a higher version.",
      "rollbackOf": "2.0.7",
      "available": true,
      "sha256": "…",
      "size": 512345
    }
  ]
}
```

Each release carries the fields you authored plus the real `sha256` and byte `size` the server computed from the CRX on
disk. A release whose CRX is not yet present shows `available` as false and omits the hash and size, which lets you
announce a version in the catalog before its package lands. The same feed is available as RSS at
`GET /updates/releases.xml` for a person who wants release notices in a feed reader.

## Serving statically with Nginx instead

If you prefer to serve updates as static files, you can, at the cost of the dynamic conveniences above. Package each
CRX, hand-write one gupdate XML manifest per channel that points at the CRX URL, and serve the directory with Nginx.

```nginx
location /updates/ {
    alias /var/lib/osprey/updates/;
    types { application/x-chrome-extension crx; }
    default_type application/octet-stream;
}
```

With static files you edit the XML by hand for every pin, staging step, and rollback, and you compute the hashes
yourself. The built-in server exists so you edit one small JSON file instead. Most operators run the built-in server;
the static option is here for those who want the update files on a plain web host separate from the proxy.

## Metrics

When the server offers a build to a browser it increments a Prometheus counter labelled by channel and version.

```
osprey_updates_served_total{channel,version}
```

Both labels are operator-controlled and bounded, so the cardinality stays small. This makes a staged rollout visible. A
query grouped by version shows how a new build spreads across a channel over time.

```promql
sum by (channel, version) (rate(osprey_updates_served_total[1h]))
```

## Firefox

Firefox does not read the Chromium gupdate manifest and does not install a CRX. It installs a signed XPI and reads its
own JSON update manifest. Enterprise distribution of a self-hosted Firefox add-on uses Firefox's own policy and update
mechanism, and the add-on must be signed through Mozilla even for in-house distribution. This update server does not
emit Firefox's format, so for a Firefox fleet use Firefox's enterprise add-on policy and its `updates.json` mechanism,
documented alongside the other cross-browser deployment templates in `OspreySite`. The Chromium server here still covers
Chrome, Edge, Brave, and Vivaldi.

## Security notes

- The update endpoints are intentionally unauthenticated, because a force-install update URL cannot carry a credential.
  Integrity comes from the CRX being signed with your private key and from the browser verifying that signature, not
  from authenticating the fetch.
- Keep the signing `.pem` key offline and backed up. It is the identity of your extension.
- Serve the update URLs over TLS through the same Nginx front end that fronts the rest of the proxy, so the manifest and
  the CRX cannot be tampered with in transit.
- The server only serves CRX files that a catalog release references, and it rejects any filename that is malformed or
  that tries to escape the updates directory, so the endpoint cannot be turned into an arbitrary file reader.

## Operations checklist

- Package each build with the same offline signing key, name it `osprey-<version>.crx`, and place it in the updates
  directory.
- Set `osprey.updates.enabled=true`, `osprey.updates.base-url` to the public origin, and `osprey.updates.app-id` to your
  extension id.
- Keep `releases.json` and `channels.json` in the updates directory, and keep every published CRX on disk for rollback.
- Point each fleet's force-install update URL at the channel it belongs to, with beta groups on the beta channel.
- Stage by moving the beta channel, promote by moving the stable channel, and roll back by republishing the good code
  under a higher version.
- Subscribe your change-management process to `GET /updates/releases.json` or its RSS form.
