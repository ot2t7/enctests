#![feature(proc_macro_quote)]

use proc_macro::{TokenStream, TokenTree, Ident, Span, Punct, Literal, quote, Spacing};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use rand::random;

fn transfer_bytes(buff: &[u8]) -> TokenStream {
    let mut elem_vec: Vec<TokenTree> = vec![];
    for n in buff {
        elem_vec.push(TokenTree::Literal(Literal::u8_suffixed(*n)));
        elem_vec.push(TokenTree::Punct(Punct::new(',', Spacing::Alone)));
    }
    let elem = TokenStream::from_iter(elem_vec.into_iter());
    let create_arr = quote! {[$elem];};
    return create_arr;
}

fn encrypt_constant(constant: &str) -> ([u8 ; 32], [u8 ; 12], Vec<u8>) {
    let random_key = random::<[u8 ; 32]>();
    let random_nonce = random::<[u8 ; 12]>();
    let key = Key::from_slice(&random_key);
    let nonce = Nonce::from_slice(&random_nonce);
    let cipher = Aes256Gcm::new(key);
    let input = constant.to_string();
    let ciphertext = cipher.encrypt(nonce, input.as_bytes())
        .expect("encryption failure!");

    return (random_key, random_nonce, ciphertext);
}

#[proc_macro]
pub fn encrypt_string(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // There must be 1 input
    let count = input.clone().into_iter().count();
    if count != 1 {
        panic!("expected one input token, got {}", count);
    }

    let first_token = input.into_iter().next().unwrap();
    let output: TokenStream;

    match litrs::Literal::try_from(first_token) {
        Err(e) => return e.to_compile_error(),

        Ok(litrs::Literal::String(s)) => {
            let mut parsed = s.to_string();
            parsed = parsed[1..parsed.len() - 1].to_string();

            let (random_key, random_nonce, ciphertext) = encrypt_constant(&parsed);
            println!("{}", String::from_utf8_lossy(&ciphertext));

            let random_key_buff = transfer_bytes(&random_key);
            let random_nonce_buff = transfer_bytes(&random_nonce);
            let ciphertext_buff = transfer_bytes(&ciphertext);

            output = quote! {
                {
                    use aes_gcm::aead::{Aead, NewAead};
                    let random_key = $random_key_buff;
                    let random_nonce = $random_nonce_buff;
                    let ciphertext = $ciphertext_buff;
    
                    let key = aes_gcm::Key::from_slice(&random_key);
                    let nonce = aes_gcm::Nonce::from_slice(&random_nonce);
                    let cipher = aes_gcm::Aes256Gcm::new(key);
    
                    let result = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
                    std::str::from_utf8(&result).unwrap().to_owned()
                }
            }
        }
        // The input must be a string literal
        Ok(other) => { panic!("expected a string literal, got {}", other); }
    }

    return output;
}