/// Tests are taken from the CryptoPals padding oracle challenge (challenge 17)
use aes::cipher::{
    block_padding::{Pkcs7, RawPadding},
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};

/// We're using predictable values here to avoid having random behaviors in our tests
const KEY: [u8; 16] = [0u8; 16];
const IV: [u8; 16] = [0u8; 16];

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

fn oracle(ciphertext: &[u8]) -> bool {
    let mut buf = ciphertext.to_vec();

    Aes128CbcDec::new(&KEY.into(), &IV.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .is_ok()
}

fn test_aes_cbc(plaintext: &[u8]) {
    // Encrypt the plaintext
    let mut ciphertext = vec![0u8; (plaintext.len() / 16 + 1) * 16];

    ciphertext[..plaintext.len()].copy_from_slice(plaintext);

    let ciphertext = Aes128CbcEnc::new(&KEY.into(), &IV.into())
        .encrypt_padded_mut::<Pkcs7>(&mut ciphertext, plaintext.len())
        .unwrap();

    // Append the IV
    let mut iv = IV.to_vec();

    iv.extend_from_slice(ciphertext);

    // Perfmor the attack
    let plaintext2 = padding_oracle::decrypt(&iv, 16, oracle).unwrap();

    // Unpad the plaintext
    let plaintext2 = Pkcs7::raw_unpad(plaintext2.as_slice()).unwrap();

    assert_eq!(plaintext, plaintext2);
}

#[test]
fn it_can_decrypt_aes_cbc_0() {
    let plaintext = b"000000Now that the party is jumping";

    test_aes_cbc(plaintext);
}

#[test]
fn it_can_decrypt_aes_cbc_1() {
    let plaintext = b"000001With the bass kicked in and the Vega's are pumpin'";

    test_aes_cbc(plaintext);
}

#[test]
fn it_can_decrypt_aes_cbc_2() {
    let plaintext = b"000002Quick to the point, to the point, no faking";

    test_aes_cbc(plaintext);
}

#[test]
fn it_can_decrypt_aes_cbc_3() {
    let plaintext = b"000003Cooking MC's like a pound of bacon";

    test_aes_cbc(plaintext);
}

#[test]
fn it_can_decrypt_aes_cbc_4() {
    let plaintext = b"000004Burning 'em, if you ain't quick and nimble";

    test_aes_cbc(plaintext);
}

#[test]
fn it_can_decrypt_aes_cbc_5() {
    let plaintext = b"000005I go crazy when I hear a cymbal";

    test_aes_cbc(plaintext);
}

#[test]
fn it_can_decrypt_aes_cbc_6() {
    let plaintext = b"000006And a high hat with a souped up tempo";

    test_aes_cbc(plaintext);
}

#[test]
fn it_can_decrypt_aes_cbc_7() {
    let plaintext = b"000007I'm on a roll, it's time to go solo";

    test_aes_cbc(plaintext);
}

#[test]
fn it_can_decrypt_aes_cbc_8() {
    let plaintext = b"000008ollin' in my five point oh";

    test_aes_cbc(plaintext);
}

#[test]
fn it_can_decrypt_aes_cbc_9() {
    let plaintext = b"000009ith my rag-top down so my hair can blow";

    test_aes_cbc(plaintext);
}
