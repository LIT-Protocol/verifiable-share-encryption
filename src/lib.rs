mod byte_proof;
mod ciphertext;
mod dlog_proof;
mod errors;
mod proof;
mod serdes;

use std::ops::Deref;
pub use byte_proof::*;
pub use ciphertext::*;
pub use dlog_proof::*;
pub use errors::*;
pub use proof::*;

use bulletproofs::{group::{
    ff::{Field, PrimeField},
    Group,
}, merlin::Transcript, BulletproofCurveArithmetic, BulletproofGens, PedersenGens, RangeProof, TranscriptProtocol};
use rand_core::{RngCore, CryptoRng};

pub trait VerifiableEncryption: BulletproofCurveArithmetic {
    fn encrypt_and_prove(
        encryption_key: Self::Point,
        key_share: &Self::Scalar,
        mut rng: impl RngCore + CryptoRng,
    ) -> (Ciphertext<Self>, Proof<Self>) {
        let mut transcript = Transcript::new(b"ElGamalVerifiableEncryption");
        let key_repr = key_share.to_repr();
        let key_bytes = key_repr.as_ref();
        let mut key_segments = [0u64; 32];
        key_segments
            .iter_mut()
            .zip(key_bytes.iter())
            .for_each(|(segment, byte)| {
                *segment = *byte as u64;
            });
        let mut blinders = [Self::Scalar::ZERO; 32];
        blinders.iter_mut().for_each(|blinder| {
            *blinder = Self::Scalar::random(&mut rng);
        });
        let bp_gens = BulletproofGens::new(8, 32);
        let pc_gens = PedersenGens {
            B: Self::Point::generator(),
            B_blinding: encryption_key,
        };
        let (range_proof, c2s) = RangeProof::prove_multiple_with_rng(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &key_segments,
            &blinders,
            8,
            &mut rng,
        )
        .unwrap();
        let mut c1s = [Self::Point::identity(); 32];
        c1s.iter_mut()
            .zip(blinders.iter())
            .for_each(|(c1, r)| *c1 = Self::Point::generator() * r);

        let mut blinder_blinders = [Self::Scalar::ZERO; 32];
        blinder_blinders
            .iter_mut()
            .for_each(|s| *s = Self::Scalar::random(&mut rng));

        transcript.append_message(b"elgamal_segment_proofs", &[32]);
        for i in 0..32 {
            transcript.append_u64(b"elgamal_segment_proofs_index", i as u64);
            transcript.append_point::<Self>(b"elgamal_segment_proofs_c1", &c1s[i]);
            transcript.append_point::<Self>(b"elgamal_segment_proofs_c2", &c2s[i]);
            let r1 = Self::Point::generator() * blinder_blinders[i];
            let r2 = Self::Point::generator() * blinders[i] + encryption_key * blinder_blinders[i];
            transcript.append_point::<Self>(b"elgamal_segment_proofs_r1", &r1);
            transcript.append_point::<Self>(b"elgamal_segment_proofs_r2", &r2);
        }

        let dlog_committing =
            DlogProof::<Self>::new(encryption_key, *key_share, &mut transcript, &mut rng);
        let challenge = transcript.challenge_scalar::<Self>(b"elgamal_segment_proofs_challenge");
        let dlog_proof = dlog_committing.finalize(challenge);

        let mut byte_proofs = [ByteProof::<Self>::default(); 32];
        byte_proofs.iter_mut().enumerate().for_each(|(i, p)| {
            p.message = blinders[i] - challenge * Self::Scalar::from(key_bytes[i] as u64);
            p.blinder = blinder_blinders[i] - challenge * blinders[i];
        });

        let mut c2 = [Self::Point::identity(); 32];
        c2.iter_mut().zip(c2s.iter()).for_each(|(c2, i)| *c2 = *i);

        (
            Ciphertext { c1: c1s, c2 },
            Proof {
                byte_proofs,
                challenge,
                dlog_proof,
                range_proof,
            },
        )
    }

    fn verify(
        encryption_key: Self::Point,
        verification_key: Self::Point,
        ciphertext: &Ciphertext<Self>,
        proof: &Proof<Self>,
    ) -> Result<()> {
        let mut transcript = Transcript::new(b"ElGamalVerifiableEncryption");
        let bp_gens = BulletproofGens::new(8, 32);
        let pc_gens = PedersenGens {
            B: Self::Point::generator(),
            B_blinding: encryption_key,
        };
        proof.range_proof.verify_multiple(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &ciphertext.c2,
            8
        ).map_err(|_e| Error::InvalidRangeProof)?;

        transcript.append_message(b"elgamal_segment_proofs", &[32]);
        for i in 0..32 {
            transcript.append_u64(b"elgamal_segment_proofs_index", i as u64);
            transcript.append_point::<Self>(b"elgamal_segment_proofs_c1", &ciphertext.c1[i]);
            transcript.append_point::<Self>(b"elgamal_segment_proofs_c2", &ciphertext.c2[i]);
            let r1 = ciphertext.c1[i] * proof.challenge + Self::Point::generator() * proof.byte_proofs[i].blinder;
            let r2 = ciphertext.c2[i] * proof.challenge + encryption_key * proof.byte_proofs[i].blinder + Self::Point::generator() * proof.byte_proofs[i].message;
            transcript.append_point::<Self>(b"elgamal_segment_proofs_r1", &r1);
            transcript.append_point::<Self>(b"elgamal_segment_proofs_r2", &r2);
        }

        transcript.append_point::<Self>(b"G", &Self::Point::generator());
        transcript.append_point::<Self>(b"Y", &encryption_key);
        transcript.append_point::<Self>(b"C1", &proof.dlog_proof.c1);
        transcript.append_point::<Self>(b"C2", &proof.dlog_proof.c2);
        transcript.append_point::<Self>(b"Q", &verification_key);
        transcript.append_point::<Self>(b"A1", &proof.dlog_proof.a1);
        transcript.append_point::<Self>(b"A2", &proof.dlog_proof.a2);
        transcript.append_point::<Self>(b"A3", &proof.dlog_proof.a3);
        let challenge = transcript.challenge_scalar::<Self>(b"elgamal_segment_proofs_challenge");

        if challenge != proof.challenge {
            return Err(Error::InvalidSegmentsProof);
        }

        //DLOG verify

        // (r1 + c.x).G
        let lhs1 = Self::Point::generator() * proof.dlog_proof.message;
        // r1.G + c.x.G
        let rhs1 = proof.dlog_proof.a1 + verification_key * challenge;

        // (r2 + c.r).Y
        let lhs2 = encryption_key * proof.dlog_proof.blinding;
        // r2.Y + c.x.G + c.r.Y - c.x.G
        let rhs2 = proof.dlog_proof.a2 + (proof.dlog_proof.c2 - verification_key) * challenge;

        // (r2 + c.r).G
        let lhs3 = Self::Point::generator() * proof.dlog_proof.blinding;
        // r2.G + c.r.G
        let rhs3 = proof.dlog_proof.a3 + proof.dlog_proof.c1 * challenge;

        if lhs1 == rhs1 && lhs2 == rhs2 && lhs3 == rhs3 {
            Ok(())
        } else {
            Err(Error::InvalidDlogProof)
        }
    }
}

pub trait VerifiableEncryptionDecryptor: BulletproofCurveArithmetic {
    fn decrypt(decryption_key: &Self::Scalar, ciphertext: Ciphertext<Self>) -> Result<Self::Scalar> {
        use rayon::prelude::*;

        let mut key_bytes = [0u8; 32];

        key_bytes.par_iter_mut().enumerate().for_each(|(i, b)|{
            let vi = ciphertext.c2[i] - ciphertext.c1[i] * *decryption_key;

            for ki in 0u8..255 {
                let si = Self::Scalar::from(ki as u64);
                if vi == Self::Point::generator() * si {
                    *b = ki;
                    break;
                }
            }
        });
        let mut repr = <Self::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&key_bytes);
        Option::<Self::Scalar>::from(Self::Scalar::from_repr(repr)).ok_or(Error::InvalidKey)
    }
}

impl VerifiableEncryption for bulletproofs::k256::Secp256k1 {}

impl VerifiableEncryptionDecryptor for bulletproofs::k256::Secp256k1 {}

impl VerifiableEncryption for bulletproofs::p256::NistP256 {}

impl VerifiableEncryptionDecryptor for bulletproofs::p256::NistP256 {}

impl VerifiableEncryption for bulletproofs::Curve25519 {}

impl VerifiableEncryptionDecryptor for bulletproofs::Curve25519 {}

impl VerifiableEncryption for bulletproofs::bls12_381_plus::Bls12381G1 {}

impl VerifiableEncryptionDecryptor for bulletproofs::bls12_381_plus::Bls12381G1 {}

impl VerifiableEncryption for bulletproofs::blstrs_plus::Bls12381G1 {}

impl VerifiableEncryptionDecryptor for bulletproofs::blstrs_plus::Bls12381G1 {}

pub trait KeyToScalar {
    type Curve: BulletproofCurveArithmetic;

    fn key_to_scalar(&self) -> <Self::Curve as BulletproofCurveArithmetic>::Scalar;
}

pub trait KeyToPoint {
    type Curve: BulletproofCurveArithmetic;

    fn key_to_point(&self) -> <Self::Curve as BulletproofCurveArithmetic>::Point;
}

impl KeyToScalar for bulletproofs::k256::SecretKey {
    type Curve = bulletproofs::k256::Secp256k1;

    fn key_to_scalar(&self) -> bulletproofs::k256::Scalar {
        *self.to_nonzero_scalar().deref()
    }
}

impl KeyToPoint for bulletproofs::k256::PublicKey {
    type Curve = bulletproofs::k256::Secp256k1;

    fn key_to_point(&self) -> bulletproofs::k256::ProjectivePoint {
        self.to_projective()
    }
}

impl KeyToScalar for bulletproofs::p256::SecretKey {
    type Curve = bulletproofs::p256::NistP256;

    fn key_to_scalar(&self) -> bulletproofs::p256::Scalar {
        *self.to_nonzero_scalar().deref()
    }
}

impl KeyToPoint for bulletproofs::p256::PublicKey {
    type Curve = bulletproofs::p256::NistP256;

    fn key_to_point(&self) -> bulletproofs::p256::ProjectivePoint {
        self.to_projective()
    }
}

#[test]
fn encrypt_and_proof_k256_works() {
    use bulletproofs::k256::{SecretKey, Secp256k1};

    let mut rng = rand::thread_rng();
    let signing_key = SecretKey::random(&mut rng);
    let verification_key = signing_key.public_key();

    let decryption_key = SecretKey::random(&mut rng);
    let encryption_key = decryption_key.public_key();

    let (ciphertext, proof) = Secp256k1::encrypt_and_prove(encryption_key.key_to_point(), &signing_key.key_to_scalar(), &mut rng);

    let res = Secp256k1::verify(encryption_key.key_to_point(), verification_key.key_to_point(), &ciphertext, &proof);
    assert!(res.is_ok());

    let res = Secp256k1::decrypt(&decryption_key.key_to_scalar(), ciphertext);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), signing_key.key_to_scalar());
}

#[test]
fn k256_proof_serde_works() {
    use bulletproofs::k256::{SecretKey, Secp256k1};

    let mut rng = rand::thread_rng();
    let signing_key = SecretKey::random(&mut rng);

    let decryption_key = SecretKey::random(&mut rng);
    let encryption_key = decryption_key.public_key();

    let (ciphertext, proof) = Secp256k1::encrypt_and_prove(encryption_key.key_to_point(), &signing_key.key_to_scalar(), &mut rng);

    let bytes = serde_bare::to_vec(&ciphertext).unwrap();
    let ciphertext2: Ciphertext<Secp256k1> = serde_bare::from_slice(&bytes).unwrap();
    assert_eq!(ciphertext.c1, ciphertext2.c1);
    assert_eq!(ciphertext.c2, ciphertext2.c2);

    let json = serde_json::to_string(&ciphertext).unwrap();
    let ciphertext2: Ciphertext<Secp256k1> = serde_json::from_str(&json).unwrap();
    assert_eq!(ciphertext.c1, ciphertext2.c1);
    assert_eq!(ciphertext.c2, ciphertext2.c2);

    let bytes = serde_bare::to_vec(&proof).unwrap();
    let proof2: Proof<Secp256k1> = serde_bare::from_slice(&bytes).unwrap();
    assert_eq!(proof.dlog_proof, proof2.dlog_proof);
    assert_eq!(proof.challenge, proof2.challenge);

    let json = serde_json::to_string(&proof).unwrap();
    let proof2: Proof<Secp256k1> = serde_json::from_str(&json).unwrap();
    assert_eq!(proof.dlog_proof, proof2.dlog_proof);
    assert_eq!(proof.challenge, proof2.challenge);
}