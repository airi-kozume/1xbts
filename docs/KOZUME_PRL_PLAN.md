# Kozume PRLs on Linux

## Existing support

This checkout already implements classic and Extended PRL editing, binary
generation, CRC computation, decoding and OTASP delivery. Windows QPST is
not required for the generation workflow. Relevant implementation paths:

- `1xbts-web/src/app/prls/new/page.tsx`: upload, create from scratch, or seed
  from a running cell.
- `1xbts-web/src/components/prl-editor`: acquisition and system tables.
- `crates/cdma-otasp/src/param/prl_ext.rs`: Extended revision 3 codec.
- `crates/cdma-hlr/src/lib/prl_proto.rs`: structured PRL conversion.
- `crates/cdma-msc/src/otasp/session.rs`: segmented SSPR download and commit.

The Vortex's read-back PRL 53423 is Extended SSPR revision 3, CRC-valid,
5930 bytes. Its reported maximum PRL size was 8192 bytes. This establishes
format support but not acceptance of a newly generated PRL.

## First handset test

Use the dashboard's PRLs page to create an Extended revision 3 PRL. For a
femtocell, manually verify each seeded field: the native SDR BTS config is
not necessarily the Airave's actual provisioning configuration.

Start with the working identity:

| Item | Test value |
| --- | --- |
| PRL ID | 65001 (locally selected version, not a network identity) |
| Preferred only | false for the first transition test |
| 1x acquisition | PCS channel list, channel 50, BC1 |
| 1x system | SID 22, any NID |
| EV-DO acquisition | Generic HRPD, BC1 channel 275 |
| EV-DO system | subnet `00800580/26` |
| System association | same geographic group and association tag 0 |
| Listed-system roaming indicator | off/home |

`65535` in the working configuration corresponds to any-NID matching in
this PRL. An eventual exact NID needs an explicit single-NID record.
For the HRPD subnet, enter 26 bits, MSB-packed as hex `00800580`, without
a common-subnet table. A sector ID whose first 26 bits match is suitable;
the current device value is `0x00800580000000000000000000000000`.

Offline prototypes generated during investigation used two acquisition
records and two associated system records, totaling 39 bytes. Both a
transition variant and a preferred-only variant passed CRC verification and
exact binary round-trip through the existing Rust codec. An explicit-NID
encoding variant totaled 41 bytes and also round-tripped. These are codec
checks, not handset interoperability results. Temporary investigation
artifacts are under `/tmp/kozume-prl-lab`; they are not durable installation
assets and are not in Git.

Decode a saved binary on Linux:

```sh
cargo run --release -p cdma-otasp --example decode_prl -- \
  --limit 20 /absolute/path/to/kozume.prl
```

Keep the original handset PRL available for recovery. Save the new PRL in
the HLR library, select it as the Vortex's per-subscriber override, and only
then enable `otasp.writes.prl`. Currently that flag is false. Avoid making
an experimental list the system default, which would affect other phones.
Use handset-initiated `*228`, inspect accepted SSPR segments and commit,
then reboot manually and read the installed PRL back. Verify its version,
CRC and contents, not just the OTASP success screen. Test 1x, EV-DO, DNS,
HTTP, calls, SMS and a further handset reboot before proceeding.

Restoring the old HLR PRL selection alone does not undo the handset write.
Recovery requires delivering the original PRL again and verifying read-back.
Keep the known-working carrier identity available during the first test so
an acquisition mistake does not also remove the provisioning path.

## Moving away from Verizon identities

Choose a lab SID/NID and an EV-DO subnet separately. The EV-DO network
identity comes from the subnet/sector prefix, not the 1x SID alone. Do not
assume an arbitrary number is globally unassigned or a reserved private SID.
Check the intended handsets' existing PRLs and the lab's identity plan.

1. Validate the minimal current-identity PRL on the Vortex first.
2. Build a transition PRL containing both current and future 1x/HRPD systems,
   with deliberate priority and associations. Provision and read it back
   while the current network still works.
3. Coordinate Airave SID/NID, MSC OTASP home-network settings, handset NAM
   home SID/NID, and EV-DO sector prefix. Preserve the functioning MIN and
   A12 credentials; changing SID does not require resetting either.
4. Verify service on the new identities before removing the old records.
5. Provision a final Kozume-only list; consider preferred-only mode after
   successful acquisition and recovery testing. That controls the behavior
   of phones carrying this list, not other people's handsets.

Keeping the already working RF channels initially isolates identity changes
from acquisition-frequency changes. A network-identity change can reduce
matches in carrier PRLs but cannot guarantee that unrelated phones will
never scan, camp or attempt registration.

## Admission controls are separate

The current MSC configuration uses open access. `access.mode = "closed"`
with `register_policy = "subscriber_only"` is the relevant 1x service
admission policy. Validate hardware identities and provisioning recovery
before enabling it. Do not infer that it automatically secures the external
Airave EV-DO path: the femtocell hosts its own access network.

In this checkout, PDSN A12 has `validate_subscribers = false` and accepts a
request with a present NAI. When enabled, its current implementation matches
the explicit `a12.subscribers` list by NAI and optional hardware ID, then
checks CHAP according to policy. HLR lookup supplies a callback IMSI; it is
not by itself the acceptance predicate. Derive an allowlist from observed
Vortex A12 identity fields and test it before enabling validation. Leaving
`accept_unverified_chap` enabled is not proof of handset authentication.
These are follow-up admission changes, not part of offline PRL generation.

No live PRL, SID/NID, admission setting or handset provisioning was changed
during this investigation.

## Investigation validation

- `cargo test --release -p cdma-otasp --test prl_ext_encoder`: 13 passed.
- Both offline draft variants and explicit-NID variants: CRC valid and exact
  encode/decode round-trip.
- `cargo fmt --all -- --check` and `git diff --check`: passed.
- Git LFS was missing. The 22 carrier fixtures were restored from origin;
  each payload matches its pointer's SHA-256 and byte count. A repository-local
  Git LFS helper and filters are configured under `.git`, outside commits.
- `cargo test --release -p cdma-otasp`: all 148 tests passed (87 unit,
  22 carrier binary round-trip, 13 Extended encoder, 26 real-PRL checks).
  The earlier carrier-suite failures were caused by unexpanded LFS pointers.
