//! Download orchestration: turn the server's opaque §8.5 file view + a D5-verified
//! author into the `client-core` `DownloadBundle`/`StreamHeader` + `VerifyContext`
//! the verify ladder consumes. Pure parsing/assembly here; the verify ladder lives
//! in client-core. Only verified, render-ready results ever reach a command.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;

use maxsecu_client_core::{DownloadBundle, Identity, StreamChunks, StreamHeader};
use maxsecu_crypto::{
    deserialize_hybrid_wrap, unwrap_dek, unwrap_dek_hybrid, Dek, HybridEncSecretKey, WrappedDek,
};
use maxsecu_encoding::structs::{Manifest, WrapContext};
use maxsecu_encoding::types::{Id, StreamType, Suite};

use crate::config::RouteMode;
use crate::direct_link::DirectLinkHttp;
use crate::error::UiError;

/// One stream's wire descriptor from a §8.5 file view (no values).
#[derive(Debug)]
pub struct StreamSpec {
    pub stream_type: StreamType,
    pub chunk_count: u64,
    pub chunk_size: u64,
}

/// The parsed, non-secret framing of a file view: which streams exist + the
/// verification records, ready to drive header/content fetches. The wrap and
/// grant bytes are inert (the recipient re-verifies them); they never reach the UI.
#[derive(Debug)]
pub struct ParsedView {
    pub version: u64,
    pub manifest_bytes: Vec<u8>,
    pub manifest_sig: [u8; 64],
    pub genesis_bytes: Vec<u8>,
    pub genesis_sig: [u8; 64],
    pub wrapped_dek: WrappedDek,
    pub grant_bytes: Vec<u8>,
    pub grant_sig: [u8; 64],
    pub ancestor_grants: Vec<(Vec<u8>, [u8; 64])>,
    pub recovery_grant_bytes: Vec<u8>,
    pub recovery_grant_sig: [u8; 64],
    pub streams: Vec<StreamSpec>,
}

fn stream_type_from_name(s: &str) -> Option<StreamType> {
    match s {
        "content" => Some(StreamType::Content),
        "metadata" => Some(StreamType::Metadata),
        "thumbnail" => Some(StreamType::Thumbnail),
        "preview" => Some(StreamType::Preview),
        _ => None,
    }
}

fn dec(json: &serde_json::Value, key: &str) -> Result<Vec<u8>, UiError> {
    B64.decode(json[key].as_str().ok_or_else(bad)?)
        .map_err(|_| bad())
}
fn dec64(json: &serde_json::Value, key: &str) -> Result<[u8; 64], UiError> {
    dec(json, key)?.try_into().map_err(|_| bad())
}
fn bad() -> UiError {
    UiError::new("fetch_failed", "The server sent a malformed file record.")
}

/// Rebuild the `enc(32) ‖ ct` wire wrap into a `WrappedDek`.
fn wrap_from_bytes(b: &[u8]) -> Result<WrappedDek, UiError> {
    if b.len() < 32 {
        return Err(bad());
    }
    Ok(WrappedDek {
        enc: b[..32].try_into().map_err(|_| bad())?,
        ct: b[32..].to_vec(),
    })
}

/// Parse a §8.5 `FileRes` JSON body into a `ParsedView` (no network, no decrypt).
pub fn parse_file_view(json: &serde_json::Value) -> Result<ParsedView, UiError> {
    let mw = &json["my_wrap"];
    let ancestor_grants = mw["ancestor_grants"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|g| Ok((dec(g, "grant_b64")?, dec64(g, "grant_sig_b64")?)))
                .collect::<Result<Vec<_>, UiError>>()
        })
        .transpose()?
        .unwrap_or_default();
    let (recovery_grant_bytes, recovery_grant_sig) = match json.get("recovery_grant") {
        Some(rg) if !rg.is_null() => (dec(rg, "grant_b64")?, dec64(rg, "grant_sig_b64")?),
        _ => (Vec::new(), [0u8; 64]),
    };
    let mut streams = Vec::new();
    for s in json["streams"].as_array().ok_or_else(bad)? {
        let name = s["stream_type"].as_str().ok_or_else(bad)?;
        let st = stream_type_from_name(name).ok_or_else(bad)?;
        streams.push(StreamSpec {
            stream_type: st,
            chunk_count: s["chunk_count"].as_u64().ok_or_else(bad)?,
            chunk_size: s["chunk_size"].as_u64().ok_or_else(bad)?,
        });
    }
    Ok(ParsedView {
        version: json["version"].as_u64().ok_or_else(bad)?,
        manifest_bytes: dec(json, "manifest_b64")?,
        manifest_sig: dec64(json, "manifest_sig_b64")?,
        genesis_bytes: dec(json, "genesis_b64")?,
        genesis_sig: dec64(json, "genesis_sig_b64")?,
        wrapped_dek: wrap_from_bytes(&dec(mw, "wrapped_dek_b64")?)?,
        grant_bytes: dec(mw, "grant_b64")?,
        grant_sig: dec64(mw, "grant_sig_b64")?,
        ancestor_grants,
        recovery_grant_bytes,
        recovery_grant_sig,
        streams,
    })
}

fn stream_name(st: StreamType) -> &'static str {
    match st {
        StreamType::Content => "content",
        StreamType::Metadata => "metadata",
        StreamType::Thumbnail => "thumbnail",
        StreamType::Preview => "preview",
    }
}

/// GET every ciphertext chunk of one stream (authed) for `file_id_hex`/`version`,
/// preferring the direct-link download route (`crate::direct_link`) under
/// [`RouteMode::PreferDropbox`] and falling back to the server-proxied GET on ANY
/// problem (link off/absent/mis-fetched — `TorOnly` never even attempts direct).
/// `host` is threaded into the Host header (see http_client::get_bytes). Returns
/// whether ANY chunk in this stream was direct-sourced, so a caller whose OWN
/// downstream verification covers this stream (`open_stream`'s whole-stream
/// digest+AEAD, run later in `client-core` — no immediate per-chunk check is
/// available at this layer for a non-`content` stream) can retry the WHOLE
/// fetch forced-proxy if that verification fails; see `build_stream_header`/
/// `build_download_bundle`.
pub async fn fetch_stream_chunks(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    file_id_hex: &str,
    version: u64,
    spec: &StreamSpec,
    route_mode: RouteMode,
    direct_http: Option<&dyn DirectLinkHttp>,
) -> Result<(StreamChunks, bool), UiError> {
    // No eager capacity hint: `chunk_count` is the UNSIGNED §8.5 listing value
    // (attacker-controlled, read before verification) — a huge value would panic
    // (capacity overflow) or OOM. The loop self-bounds: the first out-of-range
    // chunk GET returns non-OK and errors out.
    let mut chunks = Vec::new();
    let mut used_direct = false;
    for i in 0..spec.chunk_count {
        let (bytes, direct) = crate::direct_link::fetch_chunk_routed(
            sender,
            host,
            token,
            file_id_hex,
            version,
            stream_name(spec.stream_type),
            i,
            route_mode,
            direct_http,
            |_| true, // no immediate per-chunk verify available for a non-content
                      // stream at this layer; see the doc comment above.
        )
        .await?;
        used_direct |= direct;
        chunks.push(bytes);
    }
    Ok((
        StreamChunks {
            stream_type: spec.stream_type,
            chunks,
        },
        used_direct,
    ))
}

/// Build a header-only `StreamHeader` (NON-content streams only) from a parsed
/// view — for `decrypt_card`. Fetches only `metadata`/`thumbnail`/`preview`.
/// Returns whether ANY chunk across ALL fetched streams was direct-sourced (OR
/// across streams) — see [`fetch_stream_chunks`].
pub async fn build_stream_header(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    file_id_hex: &str,
    view: &ParsedView,
    route_mode: RouteMode,
    direct_http: Option<&dyn DirectLinkHttp>,
) -> Result<(StreamHeader, bool), UiError> {
    let mut small = Vec::new();
    let mut used_direct = false;
    for spec in view
        .streams
        .iter()
        .filter(|s| s.stream_type != StreamType::Content)
    {
        let (chunks, direct) = fetch_stream_chunks(
            sender,
            host,
            token,
            file_id_hex,
            view.version,
            spec,
            route_mode,
            direct_http,
        )
        .await?;
        used_direct |= direct;
        small.push(chunks);
    }
    Ok((
        StreamHeader {
            manifest_bytes: view.manifest_bytes.clone(),
            manifest_sig: view.manifest_sig,
            genesis_bytes: view.genesis_bytes.clone(),
            genesis_sig: view.genesis_sig,
            wrapped_dek: view.wrapped_dek.clone(),
            grant_bytes: view.grant_bytes.clone(),
            grant_sig: view.grant_sig,
            ancestor_grants: view.ancestor_grants.clone(),
            recovery_grant_bytes: view.recovery_grant_bytes.clone(),
            recovery_grant_sig: view.recovery_grant_sig,
            small_streams: small,
        },
        used_direct,
    ))
}

/// Build a full `DownloadBundle` (ALL streams) from a parsed view — for the
/// viewer. Returns whether ANY chunk across ALL streams was direct-sourced —
/// see [`fetch_stream_chunks`].
pub async fn build_download_bundle(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    file_id_hex: &str,
    view: &ParsedView,
    route_mode: RouteMode,
    direct_http: Option<&dyn DirectLinkHttp>,
) -> Result<(DownloadBundle, bool), UiError> {
    let mut streams = Vec::new();
    let mut used_direct = false;
    for spec in &view.streams {
        let (chunks, direct) = fetch_stream_chunks(
            sender,
            host,
            token,
            file_id_hex,
            view.version,
            spec,
            route_mode,
            direct_http,
        )
        .await?;
        used_direct |= direct;
        streams.push(chunks);
    }
    Ok((
        DownloadBundle {
            manifest_bytes: view.manifest_bytes.clone(),
            manifest_sig: view.manifest_sig,
            genesis_bytes: view.genesis_bytes.clone(),
            genesis_sig: view.genesis_sig,
            wrapped_dek: view.wrapped_dek.clone(),
            grant_bytes: view.grant_bytes.clone(),
            grant_sig: view.grant_sig,
            ancestor_grants: view.ancestor_grants.clone(),
            recovery_grant_bytes: view.recovery_grant_bytes.clone(),
            recovery_grant_sig: view.recovery_grant_sig,
            streams,
        },
        used_direct,
    ))
}

/// Recover the caller's OWN Data Encryption Key from a served §8.5 file view,
/// outside the download/viewer path (which unwraps the DEK internally and then
/// discards it — `OpenedFile`/`OpenedHeader` deliberately never expose it). The
/// reshare flow (a later task) needs the raw `Dek` to call `build_reshare`; this
/// helper is the ONLY place it is handed back to the caller.
///
/// **Security boundary — "any wrap-holder, in practice."** `my_id` MUST be the
/// AUTHENTICATED session's own user id (the caller sources it from `Session`),
/// never a client-supplied arbitrary id: it is the `recipient_id` the served
/// self-wrap is cryptographically bound to, so recovery only succeeds for a
/// caller who genuinely holds a wrap addressed to `Id(my_id)`. A caller with no
/// such wrap fails closed at the HPKE/hybrid unwrap — no wrap ⇒ no DEK. This is
/// what confines the reshare command to a holder of their own wrap (the owner
/// always is, from their upload self-wrap).
///
/// `file_id` is the REQUESTED id (caller-supplied, trusted — parsed from the URL
/// the caller asked for), NOT the served `manifest.file_id`. Binding the
/// `WrapContext` to the requested id means a server that substitutes a different
/// file's view (a wrap the caller can open for some OTHER file) fails the context
/// binding and errors out, rather than silently yielding the wrong file's DEK —
/// the same content-substitution defense the download ladder applies (P3).
///
/// **Borrow discipline.** This function is deliberately SYNCHRONOUS: the caller
/// performs the async `GET /v1/files/{id}?version=latest` + [`parse_file_view`]
/// FIRST, then invokes this with the already-parsed view and a briefly-borrowed
/// `identity`. Because nothing here `.await`s, the non-`Clone` identity borrow
/// cannot span an await point — the borrow-across-await hazard is prevented
/// structurally, not merely by convention (mirrors `streaming_confirm`'s and
/// `verify_header`'s unwrap-under-a-tight-scope pattern).
///
/// The returned [`Dek`] is an INTERNAL, in-process value: consume it immediately
/// (derive/re-wrap) and let it drop (it zeroizes). It MUST NEVER cross the Tauri
/// seam or appear in a DTO.
pub(crate) fn recover_own_dek(
    view: &ParsedView,
    file_id: [u8; 16],
    identity: &Identity,
    my_id: [u8; 16],
) -> Result<Dek, UiError> {
    let manifest: Manifest = maxsecu_encoding::decode(&view.manifest_bytes).map_err(|_| bad())?;

    // Bind the unwrap to the REQUESTED file id + this version + the authenticated
    // caller's own id. The served self-wrap opens only if it was genuinely made
    // for exactly this (file, version, recipient) — otherwise the AEAD `info`
    // differs and open fails.
    let ctx = WrapContext {
        file_id: Id(file_id),
        version: manifest.version,
        recipient_id: Id(my_id),
    };
    let dek = match manifest.alg {
        Suite::V1 => unwrap_dek(identity.enc_secret(), &view.wrapped_dek, &ctx)
            .map_err(|_| verify_failed())?,
        Suite::V2 => {
            let seed = identity.mlkem_seed().ok_or_else(verify_failed)?;
            // Reassemble the fixed 1168-byte hybrid wire from the `enc ‖ ct`
            // byte-carrier, mirroring `client-core::upload::unpack_hybrid_wrap`.
            let mut wire = Vec::with_capacity(32 + view.wrapped_dek.ct.len());
            wire.extend_from_slice(&view.wrapped_dek.enc);
            wire.extend_from_slice(&view.wrapped_dek.ct);
            let hybrid = deserialize_hybrid_wrap(&wire).map_err(|_| verify_failed())?;
            let hsk =
                HybridEncSecretKey::from_components(identity.enc_secret().expose_bytes(), seed);
            unwrap_dek_hybrid(&hsk, &hybrid, &ctx).map_err(|_| verify_failed())?
        }
    };

    // Self-validate against the manifest commitment (exactly as `verify_header`
    // does); a mismatch is fail-closed, never a silent proceed.
    if dek.commit() != manifest.dek_commit.0 {
        return Err(verify_failed());
    }
    Ok(dek)
}

/// Sanitized fail-closed error for a DEK-recovery failure (unopenable wrap,
/// malformed hybrid wire, missing PQ key, or a commitment mismatch) — no detail
/// leak, mirroring [`bad`].
fn verify_failed() -> UiError {
    UiError::new(
        "verify_failed",
        "Could not recover the file key from your own wrap.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view_json() -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "manifest_b64": B64.encode([1u8; 8]),
            "manifest_sig_b64": B64.encode([2u8; 64]),
            "genesis_b64": B64.encode([3u8; 8]),
            "genesis_sig_b64": B64.encode([4u8; 64]),
            "my_wrap": {
                "wrapped_dek_b64": B64.encode([9u8; 64]), // 32 enc + 32 ct
                "grant_b64": B64.encode([5u8; 8]),
                "grant_sig_b64": B64.encode([6u8; 64]),
                "ancestor_grants": []
            },
            "recovery_grant": { "grant_b64": B64.encode([7u8; 8]), "grant_sig_b64": B64.encode([8u8; 64]) },
            "streams": [
                { "stream_type": "content", "chunk_count": 3, "chunk_size": 4096, "blob_ref": "x" },
                { "stream_type": "metadata", "chunk_count": 1, "chunk_size": 4096, "blob_ref": "y" }
            ]
        })
    }

    #[test]
    fn parses_a_well_formed_view() {
        let p = parse_file_view(&view_json()).unwrap();
        assert_eq!(p.version, 1);
        assert_eq!(p.wrapped_dek.enc, [9u8; 32]);
        assert_eq!(p.wrapped_dek.ct, vec![9u8; 32]);
        assert_eq!(p.streams.len(), 2);
        assert_eq!(p.streams[0].stream_type, StreamType::Content);
        assert_eq!(p.streams[0].chunk_count, 3);
    }

    #[test]
    fn missing_recovery_grant_is_tolerated() {
        let mut j = view_json();
        j["recovery_grant"] = serde_json::Value::Null;
        let p = parse_file_view(&j).unwrap();
        assert!(p.recovery_grant_bytes.is_empty());
    }

    #[test]
    fn malformed_view_is_a_sanitized_error() {
        let bad = serde_json::json!({ "version": "nope" });
        assert_eq!(parse_file_view(&bad).unwrap_err().code, "fetch_failed");
    }

    #[test]
    fn parses_content_chunk_size() {
        let p = parse_file_view(&view_json()).unwrap();
        let content = p
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Content)
            .unwrap();
        assert_eq!(content.chunk_size, 4096);
    }

    // ── recover_own_dek (T4 step 6) ─────────────────────────────────────────
    //
    // These exercise the DEK-recovery seam the reshare command (a later task)
    // needs: recover the caller's OWN DEK from the served self-wrap, fail-closed
    // for anyone who does not hold a wrap addressed to them.

    use maxsecu_client_core::Identity;
    use maxsecu_crypto::{
        serialize_hybrid_wrap, wrap_dek, wrap_dek_hybrid, Dek, EncPublicKey, HybridEncPublicKey,
    };
    use maxsecu_encoding::structs::{Manifest, WrapContext};
    use maxsecu_encoding::types::{Bytes32, FileType, Id, Suite, Timestamp};

    /// A `ParsedView` carrying only the fields `recover_own_dek` reads (the
    /// served self-wrap + the signed manifest bytes); the rest are inert.
    fn view_with(wrapped_dek: WrappedDek, manifest_bytes: Vec<u8>, version: u64) -> ParsedView {
        ParsedView {
            version,
            manifest_bytes,
            manifest_sig: [0u8; 64],
            genesis_bytes: Vec::new(),
            genesis_sig: [0u8; 64],
            wrapped_dek,
            grant_bytes: Vec::new(),
            grant_sig: [0u8; 64],
            ancestor_grants: Vec::new(),
            recovery_grant_bytes: Vec::new(),
            recovery_grant_sig: [0u8; 64],
            streams: Vec::new(),
        }
    }

    /// Encode a minimal signed-manifest body — only `alg`, `version`, and
    /// `dek_commit` are consulted by `recover_own_dek`.
    fn manifest_bytes(
        file_id: [u8; 16],
        version: u64,
        alg: Suite,
        dek_commit: [u8; 32],
    ) -> Vec<u8> {
        maxsecu_encoding::encode(&Manifest {
            file_id: Id(file_id),
            version,
            file_type: FileType::Video,
            alg,
            chunk_size: 4096,
            dek_commit: Bytes32(dek_commit),
            streams: Vec::new(),
            recovery_present: false,
            author_id: Id([0u8; 16]),
            created_at: Timestamp(0),
        })
    }

    #[test]
    fn recovers_own_v1_self_wrap() {
        let me = Identity::generate();
        let my_id = [7u8; 16];
        let file_id = [3u8; 16];
        let version = 5u64;
        let dek = Dek::from_bytes([0x11; 32]);
        let ctx = WrapContext {
            file_id: Id(file_id),
            version,
            recipient_id: Id(my_id),
        };
        let wrapped = wrap_dek(&EncPublicKey::from_bytes(me.enc_pub_bytes()), &dek, &ctx).unwrap();
        let mb = manifest_bytes(file_id, version, Suite::V1, dek.commit());
        let view = view_with(wrapped, mb, version);

        let out = recover_own_dek(&view, file_id, &me, my_id).expect("own V1 wrap opens");
        assert_eq!(
            out.commit(),
            dek.commit(),
            "recovered DEK matches the commitment"
        );
    }

    #[test]
    fn no_matching_wrap_fails_closed() {
        // The served self-wrap is addressed to a STRANGER (a different key +
        // recipient_id). A caller who holds no wrap for themselves cannot open
        // it — this is the "any wrap-holder, in practice" boundary.
        let me = Identity::generate();
        let stranger = Identity::generate();
        let my_id = [7u8; 16];
        let stranger_id = [8u8; 16];
        let file_id = [3u8; 16];
        let version = 5u64;
        let dek = Dek::from_bytes([0x11; 32]);
        let stranger_ctx = WrapContext {
            file_id: Id(file_id),
            version,
            recipient_id: Id(stranger_id),
        };
        let wrapped = wrap_dek(
            &EncPublicKey::from_bytes(stranger.enc_pub_bytes()),
            &dek,
            &stranger_ctx,
        )
        .unwrap();
        let mb = manifest_bytes(file_id, version, Suite::V1, dek.commit());
        let view = view_with(wrapped, mb, version);

        match recover_own_dek(&view, file_id, &me, my_id) {
            Ok(_) => panic!("a non-holder must NOT recover the DEK"),
            Err(e) => assert_eq!(e.code, "verify_failed", "no wrap for me ⇒ fail closed"),
        }
    }

    #[test]
    fn recovers_own_v2_hybrid_self_wrap() {
        let me = Identity::generate();
        let my_id = [7u8; 16];
        let file_id = [3u8; 16];
        let version = 2u64;
        let dek = Dek::from_bytes([0x22; 32]);
        let ctx = WrapContext {
            file_id: Id(file_id),
            version,
            recipient_id: Id(my_id),
        };
        let pk = HybridEncPublicKey {
            x25519: me.enc_pub_bytes(),
            mlkem: me.mlkem_pub_bytes().expect("fresh identity is PQ-capable"),
        };
        let h = wrap_dek_hybrid(&pk, &dek, &ctx).unwrap();
        // Store form is the 1168-byte hybrid wire split enc(32) ‖ ct, exactly as
        // `client-core::upload::pack_hybrid_wrap` produces it.
        let wire = serialize_hybrid_wrap(&h);
        let wrapped = WrappedDek {
            enc: wire[..32].try_into().unwrap(),
            ct: wire[32..].to_vec(),
        };
        let mb = manifest_bytes(file_id, version, Suite::V2, dek.commit());
        let view = view_with(wrapped, mb, version);

        let out = recover_own_dek(&view, file_id, &me, my_id).expect("own V2 wrap opens");
        assert_eq!(
            out.commit(),
            dek.commit(),
            "recovered hybrid DEK matches commitment"
        );
    }
}
