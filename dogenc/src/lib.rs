use proc_macro::{TokenStream, TokenTree, Ident, Span, Punct, Literal};
use quote::{quote, ToTokens, TokenStreamExt};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use rand::random;

fn transfer_bytes(ident: &str, buff: &[u8]) -> TokenStream {
    let mut tokens: Vec<TokenTree> = vec![];

    tokens.push(TokenTree::Ident(Ident::new("let", Span::call_site())));
    tokens.push(TokenTree::Ident(Ident::new(ident, Span::call_site())));
    tokens.push(TokenTree::Punct(Punct::new('=', proc_macro::Spacing::Alone)));
    tokens.push(TokenTree::Punct(Punct::new('[', proc_macro::Spacing::Alone)));
    for n in buff {
        tokens.push(TokenTree::Literal(Literal::u8_suffixed(*n)));
    }
    tokens.push(TokenTree::Punct(Punct::new(']', proc_macro::Spacing::Alone)));

    return proc_macro::quote!()
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
            let random_key = random::<[u8 ; 32]>();
            let random_nonce = random::<[u8 ; 12]>();
            let key = Key::from_slice(&random_key);
            let nonce = Nonce::from_slice(&random_nonce);
            let cipher = Aes256Gcm::new(key);
            let input = s.to_string();
            let ciphertext = cipher.encrypt(nonce, input.as_bytes())
                .expect("encryption failure!");
            println!("{}", String::from_utf8_lossy(&ciphertext));

            output = transfer_bytes("something", &random_key);
        }
        // The input must be a string literal
        Ok(other) => { panic!("expected a string literal, got {}", other); }
    }

    return output;
}