extern crate proc_macro;
use proc_macro::TokenStream;
use std::ops::DerefMut;
use syn::parse::{Parse, ParseStream};
use syn::token::Async;
use syn::{Pat, Token, Type, parse_macro_input};

struct Route {
    method: syn::Ident,
    path: syn::LitStr,
}
impl Parse for Route {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let method: syn::Ident = input.parse().expect("Expected method identifier");
        input.parse::<Token![,]>()?;
        let path: syn::LitStr = input.parse().expect("missing a request path");

        Ok(Route { method, path })
    }
}

#[proc_macro_attribute]
pub fn route(attr: TokenStream, item: TokenStream) -> TokenStream {
    let route = syn::parse_macro_input!(attr as Route);

    let item_fn = syn::parse_macro_input!(item as syn::ItemFn);

    let mut inputs = item_fn.sig.inputs.clone();
    let parms: Vec<_> = inputs
        .iter_mut()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(syn::PatType { pat, .. }) => {
                let pat = if let Pat::Ident(pat_ident) = pat.deref_mut() {
                    pat_ident.by_ref = None;
                    pat_ident.mutability = None;
                    let ident = &pat_ident.ident;
                    quote::quote! {
                        #ident
                    }
                } else {
                    quote::quote! {
                        #pat
                    }
                };
                Some(pat)
            }
            _ => None,
        })
        .collect();

    let fn_name = &item_fn.sig.ident;

    let method = &route.method;
    let path = &route.path;
    quote::quote! {
        #item_fn
        weblib::register_route!(
            #method,
            #path,
            async |#inputs| {
                use weblib::result::ToResponse;
                #fn_name(#(#parms),*).await.to_response()
            }
        );
    }
    .into()
}

#[proc_macro_attribute]
pub fn router_config(_: TokenStream, item: TokenStream) -> TokenStream {
    let mut item_fn = syn::parse_macro_input!(item as syn::ItemFn);
    if item_fn.sig.asyncness.is_none() {
        item_fn.sig.asyncness = Some(Async {
            span: proc_macro2::Span::call_site(),
        });
    }

    let fn_name = &item_fn.sig.ident;

    quote::quote! {
        #item_fn
        weblib::register_router_config!(
            #fn_name
        );
    }
    .into()
}

struct BuilderConfig {
    internal: bool,
    wait_for: Vec<Type>,
}
impl Parse for BuilderConfig {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut internal = false;
        let mut wait_for: Vec<Type> = Vec::new();
        while !input.is_empty() {
            let ident: syn::Ident = input.parse()?;
            match ident.to_string().as_str() {
                "internal" => internal = true,

                "wait_for" => {
                    input.parse::<Token![=]>()?;
                    let first: Type = input.parse()?;
                    wait_for.push(first);

                    // 后续的 `, TypePath`
                    while input.peek(Token![,]) {
                        input.parse::<Token![,]>()?;
                        if input.peek(syn::Ident) {
                            let fork = input.fork();
                            let next: syn::Ident = fork.parse()?;
                            let s = next.to_string();
                            if s == "internal" || s == "wait_for" {
                                break;
                            }
                        }
                        let ty: Type = input.parse()?;
                        wait_for.push(ty);
                    }
                }

                _ => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!("未知参数: {}", ident),
                    ));
                }
            }
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(BuilderConfig { internal, wait_for })
    }
}
#[doc = include_str!("../doc/init_macro.md")]
#[proc_macro_attribute]
pub fn bean(attr: TokenStream, item: TokenStream) -> TokenStream {
    let builder_config = parse_macro_input!(attr as BuilderConfig);

    let item_fn = syn::parse_macro_input!(item as syn::ItemFn);
    let fn_name = &item_fn.sig.ident;

    let register_bean = if builder_config.internal {
        quote::quote! { crate::register_bean }
    } else {
        quote::quote! { weblib::register_bean }
    };
    let wait_for = &builder_config.wait_for;

    quote::quote! {
        #item_fn
        #register_bean!(#fn_name, #(#wait_for),*);
    }
    .into()
}
