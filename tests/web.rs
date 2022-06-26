use tetanus::keys::private::*;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn get_private_wif() {
    let wif = PrivateKey::from_login("test", "test", "owner").to_string();

    assert_eq!("5K8AruCpTY6gVeQRMd5UpeuoVR2YheRCjUDAVFrfiahZU4bBccj", wif)
}

#[wasm_bindgen_test]
fn login_equals_new() {
    let private1 = PrivateKey::new(vec![172, 77, 224, 92, 161, 163, 181, 53, 80, 219, 255, 168, 223, 31, 231, 32, 238, 108, 150, 219, 77, 153, 8, 68, 240, 148, 105, 203, 131, 235, 219, 82]);
    let private2 = PrivateKey::from_login("test", "test", "owner");
    assert_eq!(private1, private2)
}