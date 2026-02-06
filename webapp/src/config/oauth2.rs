use async_trait::async_trait;
use axum::response::Redirect;
use oauth2::basic::{
    BasicClient, BasicErrorResponse, BasicErrorResponseType, BasicRevocationErrorResponse,
    BasicTokenIntrospectionResponse, BasicTokenResponse,
};
use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
    DeviceAuthorizationUrl, EndpointMaybeSet, EndpointNotSet, EndpointSet, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RefreshToken, RevocationUrl, Scope, StandardErrorResponse,
    StandardRevocableToken, TokenResponse, TokenUrl,
};
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreClient, CoreGenderClaim,
    CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreProviderMetadata,
    CoreTokenIntrospectionResponse, CoreTokenResponse, CoreUserInfoClaims,
};
use openidconnect::TokenResponse as OpenIdConnectResponse;
use openidconnect::{AccessTokenHash, EmptyAdditionalClaims, IssuerUrl, Nonce};
use std::collections::HashMap;
use std::error::Error;
use std::ops::Deref;
use weblib::bean;

pub type OAuth2ClientType = Client<
    BasicErrorResponse,
    BasicTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointSet,
    EndpointNotSet,
    EndpointSet,
    EndpointSet,
>;

pub enum LoginClientSource {
    Google(LoginClient<OidcClientType, openidconnect::reqwest::Client>),
    Github(LoginClient<OAuth2ClientType, oauth2::reqwest::Client>),
}

pub struct LoginClientManager(HashMap<String, LoginClientSource>);

impl Deref for LoginClientManager {
    type Target = HashMap<String, LoginClientSource>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[bean]
pub async fn login_client_manager() -> Result<LoginClientManager, Box<dyn Error>> {
    let mut map: HashMap<String, LoginClientSource> = HashMap::new();
    map.insert(
        "google".to_owned(),
        LoginClientSource::Google(google_client().await?),
    );
    map.insert(
        "github".to_owned(),
        LoginClientSource::Github(github_client().await?),
    );
    Ok(LoginClientManager(map))
}

pub struct LoginClient<ClientType, HttpClient>(ClientType, HttpClient);
async fn github_client()
-> Result<LoginClient<OAuth2ClientType, oauth2::reqwest::Client>, Box<dyn Error>> {
    let client_id = "";
    let client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_client_secret(ClientSecret::new(
            "".to_string(),
        ))
        .set_auth_uri(AuthUrl::new(
            "https://github.com/login/oauth/authorize".to_string(),
        )?)
        .set_token_uri(TokenUrl::new(
            "https://github.com/login/oauth/access_token".to_string(),
        )?)
        .set_revocation_url(RevocationUrl::new(format!(
            "https://api.github.com/applications/{client_id}/token"
        ))?)
        .set_redirect_uri(RedirectUrl::new(
            "http://127.0.0.1:8080/login/oauth2/code?login_type=github".to_string(),
        )?)
        .set_device_authorization_url(DeviceAuthorizationUrl::new(
            "https://github.com/login/device/code".to_string(),
        )?);
    Ok(LoginClient(
        client,
        oauth2::reqwest::Client::builder()
            .redirect(oauth2::reqwest::redirect::Policy::none())
            .proxy(oauth2::reqwest::Proxy::all("http://127.0.0.1:7897")?)
            .build()?,
    ))
}

pub type OidcClientType = openidconnect::Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<BasicErrorResponseType>,
    CoreTokenResponse,
    CoreTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

async fn google_client()
-> Result<LoginClient<OidcClientType, openidconnect::reqwest::Client>, Box<dyn Error>> {
    let http_client = openidconnect::reqwest::Client::builder()
        .proxy(openidconnect::reqwest::Proxy::all("http://127.0.0.1:7897")?)
        .build()?;
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new("https://accounts.google.com".to_string())?,
        &http_client,
    )
    .await?;
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(
            "".to_string(),
        ),
        Some(ClientSecret::new(
            "".to_string(),
        )),
    )
    .set_revocation_url(RevocationUrl::new(
        "https://oauth2.googleapis.com/revoke".to_string(),
    )?)
    .set_redirect_uri(RedirectUrl::new(
        "http://127.0.0.1:8080/login/oauth2/code?login_type=google".to_string(),
    )?);
    Ok(LoginClient(client, http_client))
}

#[async_trait]
pub trait OAuth2Login {
    type TokenResponseType;
    type UserInfoType;

    async fn authorize_url(
        &self,
        scopes: impl IntoIterator<Item = String> + Send + Sync,
    ) -> Result<(String, String, String, Redirect), Box<dyn Error + Send + Sync>>;
    async fn exchange_code(
        &self,
        code: String,
        pkce_verifier: String,
        nonce: String,
    ) -> Result<Self::TokenResponseType, Box<dyn Error + Send + Sync>>;
    async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Self::TokenResponseType, Box<dyn Error + Send + Sync>>;
    async fn revoke_access_token(
        &self,
        access_token: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;
    async fn revoke_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    async fn userinfo(
        &self,
        access_token: &str,
    ) -> Result<Self::UserInfoType, Box<dyn Error + Send + Sync>>;
}
#[async_trait]
impl OAuth2Login for LoginClient<OidcClientType, openidconnect::reqwest::Client> {
    type TokenResponseType = CoreTokenResponse;
    type UserInfoType = CoreUserInfoClaims;
    async fn authorize_url(
        &self,
        scopes: impl IntoIterator<Item = String> + Send + Sync,
    ) -> Result<(String, String, String, Redirect), Box<dyn Error + Send + Sync>> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let scopes: Vec<Scope> = scopes.into_iter().map(Scope::new).collect();
        let (auth_url, csrf_token, nonce) = self
            .0
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scopes(scopes)
            .set_pkce_challenge(pkce_challenge)
            .url();
        Ok((
            csrf_token.secret().to_string(),
            pkce_verifier.secret().to_string(),
            nonce.secret().to_string(),
            Redirect::to(auth_url.as_ref()),
        ))
    }

    async fn exchange_code(
        &self,
        code: String,
        pkce_verifier: String,
        nonce: String,
    ) -> Result<Self::TokenResponseType, Box<dyn Error + Send + Sync>> {
        let token_response = self
            .0
            .exchange_code(AuthorizationCode::new(code))?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(&self.1)
            .await?;
        let id_token = token_response.id_token().ok_or("id_token not found")?;

        let id_token_verifier = self.0.id_token_verifier();
        let claims = id_token.claims(&id_token_verifier, &Nonce::new(nonce))?;
        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                id_token.signing_alg()?,
                id_token.signing_key(&id_token_verifier)?,
            )?;
            if actual_access_token_hash != *expected_access_token_hash {
                return Err("Invalid access token".into());
            }
        }
        Ok(token_response)
    }

    async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Self::TokenResponseType, Box<dyn Error + Send + Sync>> {
        let refresh_token = RefreshToken::new(refresh_token.to_string());
        self.0
            .exchange_refresh_token(&refresh_token)?
            .request_async(&self.1)
            .await
            .map_err(Into::into)
    }

    async fn revoke_access_token(
        &self,
        access_token: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let access_token =
            StandardRevocableToken::AccessToken(AccessToken::new(access_token.to_string()));
        self.0
            .revoke_token(access_token)?
            .request_async(&self.1)
            .await
            .map_err(Into::into)
    }

    async fn revoke_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let refresh_token =
            StandardRevocableToken::RefreshToken(RefreshToken::new(refresh_token.to_string()));
        self.0
            .revoke_token(refresh_token)?
            .request_async(&self.1)
            .await
            .map_err(Into::into)
    }

    async fn userinfo(
        &self,
        access_token: &str,
    ) -> Result<Self::UserInfoType, Box<dyn Error + Send + Sync>> {
        self.0
            .user_info(AccessToken::new(access_token.to_string()), None)?
            .request_async(&self.1)
            .await
            .map_err(Into::into)
    }
}

#[async_trait]
impl OAuth2Login for LoginClient<OAuth2ClientType, oauth2::reqwest::Client> {
    type TokenResponseType = BasicTokenResponse;
    type UserInfoType = ();

    async fn authorize_url(
        &self,
        scopes: impl IntoIterator<Item = String> + Send + Sync,
    ) -> Result<(String, String, String, Redirect), Box<dyn Error + Send + Sync>> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let scopes: Vec<Scope> = scopes.into_iter().map(Scope::new).collect();
        let (auth_url, csrf_token) = self
            .0
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes)
            .set_pkce_challenge(pkce_challenge)
            .url();
        Ok((
            csrf_token.secret().to_string(),
            pkce_verifier.secret().to_string(),
            String::new(),
            Redirect::to(auth_url.as_ref()),
        ))
    }

    async fn exchange_code(
        &self,
        code: String,
        pkce_verifier: String,
        _nonce: String,
    ) -> Result<Self::TokenResponseType, Box<dyn Error + Send + Sync>> {
        self.0
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(&self.1)
            .await
            .map_err(Into::into)
    }

    async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Self::TokenResponseType, Box<dyn Error + Send + Sync>> {
        self.0
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request_async(&self.1)
            .await
            .map_err(Into::into)
    }

    async fn revoke_access_token(
        &self,
        access_token: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.0
            .revoke_token(StandardRevocableToken::AccessToken(AccessToken::new(
                access_token.to_string(),
            )))?
            .request_async(&self.1)
            .await
            .map_err(Into::into)
    }

    async fn revoke_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.0
            .revoke_token(StandardRevocableToken::RefreshToken(RefreshToken::new(
                refresh_token.to_string(),
            )))?
            .request_async(&self.1)
            .await
            .map_err(Into::into)
    }

    async fn userinfo(
        &self,
        _access_token: &str,
    ) -> Result<Self::UserInfoType, Box<dyn Error + Send + Sync>> {
        Err("Not implemented".into())
    }
}
