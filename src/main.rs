use oqs::*;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};

fn main() -> Result<()> {
    // 构造具体的算法
    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium2)?;
    let kemalg = kem::Kem::new(kem::Algorithm::Kyber512)?;
    // 构造公私钥  keygen
    // A's long-term secrets
    let (a_sig_pk, a_sig_sk) = sigalg.keypair()?;
    // B's long-term secrets
    let (b_sig_pk, b_sig_sk) = sigalg.keypair()?;

    // assumption: A has (a_sig_sk, a_sig_pk, b_sig_pk)
    // assumption: B has (b_sig_sk, b_sig_pk, a_sig_pk)

    // A -> B: kem_pk, signature
    let (kem_pk, kem_sk) = kemalg.keypair()?;
    let signature = sigalg.sign(kem_pk.as_ref(), &a_sig_sk)?;

    // B -> A: kem_ct, signature
    sigalg.verify(kem_pk.as_ref(), &signature, &a_sig_pk)?;

    let (kem_ct, b_kem_ss) = kemalg.encapsulate(&kem_pk)?;

    // println!("{:?}", b_kem_ss);

    let signature = sigalg.sign(kem_ct.as_ref(), &b_sig_sk)?;

    // A verifies, decapsulates, now both have kem_ss
    sigalg.verify(kem_ct.as_ref(), &signature, &b_sig_pk)?;
    let a_kem_ss = kemalg.decapsulate(&kem_sk, &kem_ct)?;
    // println!("{:?}", a_kem_ss.as_ref());
    assert_eq!(a_kem_ss, b_kem_ss);

    // a_kem_ss will be ase's key

    // let key = Aes256Gcm::generate_key(&mut OsRng);
    // let cipher = Aes256Gcm::new(&key);

    let key = Key::<Aes256Gcm>::from_slice(a_kem_ss.as_ref());

    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(nonce, b"songjian".as_ref()).unwrap();
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    let message = String::from_utf8(plaintext).expect("Found invalid UTF-8");

    println!("{:?}", message);
    Ok(())
}
