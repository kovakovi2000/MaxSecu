//! Randomized round-trip + tamper property tests for the Phase-0 crypto exit
//! gate (DESIGN §17): encrypt→decrypt, wrap→unwrap, sign→verify, and framing
//! tamper-rejection, over arbitrary inputs.

use maxsecu_crypto::{
    generate_enc_keypair, open_stream, seal_stream, unwrap_dek, wrap_dek, Dek, SigningKey,
};
use maxsecu_encoding::structs::WrapContext;
use maxsecu_encoding::types::{Id, StreamType};
use proptest::prelude::*;

fn stream_type() -> impl Strategy<Value = StreamType> {
    prop_oneof![
        Just(StreamType::Content),
        Just(StreamType::Metadata),
        Just(StreamType::Thumbnail),
        Just(StreamType::Preview),
    ]
}

proptest! {
    // encrypt → decrypt: a sealed stream of arbitrary bytes round-trips.
    #[test]
    fn stream_encrypt_decrypt_round_trips(
        ck in any::<[u8; 32]>(),
        fid in any::<[u8; 16]>(),
        version in any::<u64>(),
        st in stream_type(),
        chunk_size in 16usize..4096,
        plaintext in proptest::collection::vec(any::<u8>(), 0..8192),
    ) {
        let sealed = seal_stream(&ck, Id(fid), version, st, chunk_size, &plaintext);
        prop_assert!(sealed.chunk_count >= 1);
        let out = open_stream(&ck, Id(fid), version, st, &sealed.chunks).unwrap();
        prop_assert_eq!(out, plaintext);
    }

    // framing tamper-reject: flipping any ciphertext bit makes the stream fail.
    #[test]
    fn stream_tamper_is_rejected(
        ck in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 1..4096),
        flip_byte in any::<prop::sample::Index>(),
    ) {
        let fid = Id([7u8; 16]);
        let mut sealed = seal_stream(&ck, fid, 1, StreamType::Content, 256, &plaintext);
        // Flip a bit in some chunk's ciphertext.
        let ci = flip_byte.index(sealed.chunks.len());
        let bi = flip_byte.index(sealed.chunks[ci].len());
        sealed.chunks[ci][bi] ^= 0x80;
        prop_assert!(open_stream(&ck, fid, 1, StreamType::Content, &sealed.chunks).is_err());
    }

    // sign → verify: a signature verifies, and any message tamper breaks it.
    #[test]
    fn sign_verify_round_trips_and_detects_tamper(
        seed in any::<[u8; 32]>(),
        msg in proptest::collection::vec(any::<u8>(), 0..512),
        flip in any::<prop::sample::Index>(),
    ) {
        let sk = SigningKey::from_seed(&seed);
        let vk = sk.verifying_key();
        let sig = sk.sign_raw(&msg);
        prop_assert!(vk.verify_raw(&msg, &sig).is_ok());

        let mut tampered = msg.clone();
        if tampered.is_empty() {
            tampered.push(0x00);
        } else {
            let i = flip.index(tampered.len());
            tampered[i] ^= 0x01;
        }
        prop_assert!(vk.verify_raw(&tampered, &sig).is_err());
    }
}

proptest! {
    // wrap → unwrap is heavier (HPKE keygen per case), so use fewer cases.
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn wrap_unwrap_round_trips_and_binds_context(
        dek_bytes in any::<[u8; 32]>(),
        fid in any::<[u8; 16]>(),
        version in any::<u64>(),
        rid in any::<[u8; 16]>(),
        other_rid in any::<[u8; 16]>(),
    ) {
        prop_assume!(rid != other_rid);
        let (sk, pk) = generate_enc_keypair();
        let dek = Dek::from_bytes(dek_bytes);
        let ctx = WrapContext { file_id: Id(fid), version, recipient_id: Id(rid) };
        let wrapped = wrap_dek(&pk, &dek, &ctx).unwrap();

        let recovered = unwrap_dek(&sk, &wrapped, &ctx).unwrap();
        prop_assert_eq!(recovered.expose(), &dek_bytes);

        let wrong = WrapContext { file_id: Id(fid), version, recipient_id: Id(other_rid) };
        prop_assert!(unwrap_dek(&sk, &wrapped, &wrong).is_err());
    }
}
