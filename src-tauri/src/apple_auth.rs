use std::{sync::Arc, time::Duration};

use http::Extensions;
use isideload::{
    anisette::AnisetteClientInfo,
    auth::apple_account::AppleAccount,
    sideload::cert_identity::APPLE_ROOT,
};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONNECTION, RETRY_AFTER},
    Client, Request, Response, StatusCode,
};
use reqwest_middleware::{ClientBuilder, Middleware, Next};
use rootcause::{option_ext::OptionExt, prelude::*};

const MAX_TOKEN_RETRIES: u32 = 2;
const MAX_RETRY_WAIT: Duration = Duration::from_secs(15);

/// Installs a fresh HTTP/1.1 transport before the Apple account login begins.
/// This avoids reusing an HTTP/2 connection for sequential GrandSlam requests.
pub fn configure_transport(account: &mut AppleAccount) -> Result<(), Report> {
    let grandslam = Arc::get_mut(&mut account.grandslam_client)
        .context("Apple authentication transport is already in use")?;

    normalize_legacy_client_info(&mut grandslam.client_info);
    grandslam.client = ClientBuilder::new(build_http_client()?)
        .with(DeveloperTokenRetry)
        .build();

    Ok(())
}

fn build_http_client() -> Result<Client, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("close"));

    Client::builder()
        .add_root_certificate(reqwest::Certificate::from_der(APPLE_ROOT)?)
        // HTTP/2 does not honor Connection: close; force a fresh HTTP/1.1 connection.
        .http1_only()
        .http1_title_case_headers()
        .pool_max_idle_per_host(0)
        .default_headers(headers)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(45))
        .build()
}

fn normalize_legacy_client_info(info: &mut AnisetteClientInfo) {
    const BLOCKED: &str = "com.apple.dt.Xcode/";

    if let Some(start) = info.client_info.find(BLOCKED) {
        let end = info.client_info[start..]
            .find([')', '>', ' ', '<'])
            .map_or(info.client_info.len(), |offset| start + offset);
        info.client_info
            .replace_range(start..end, "com.apple.akd/1.0");
        info.user_agent = "akd/1.0 CFNetwork/808.1.4".to_string();
    }
}

fn is_token_request(request: &Request) -> bool {
    if request.method() != reqwest::Method::POST
        || request.url().path() != "/grandslam/GsService2"
    {
        return false;
    }

    let Some(body) = request.body().and_then(|body| body.as_bytes()) else {
        return false;
    };
    if body.len() > 128 * 1024 {
        return false;
    }

    // Inspect only the plist operation name; never log authentication payloads.
    plist::Value::from_reader(std::io::Cursor::new(body))
        .ok()
        .and_then(|value| {
            value
                .as_dictionary()?
                .get("Request")?
                .as_dictionary()?
                .get("o")?
                .as_string()
                .map(|operation| operation == "apptokens")
        })
        .unwrap_or(false)
}

fn is_temporary_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn retry_wait(headers: &HeaderMap, retry: u32) -> Option<Duration> {
    let backoff = Duration::from_secs(2 << retry);
    let requested = headers
        .get(RETRY_AFTER)
        .and_then(|header| header.to_str().ok())
        .and_then(|value| {
            value
                .parse::<u64>()
                .ok()
                .map(Duration::from_secs)
                .or_else(|| {
                    chrono::DateTime::parse_from_rfc2822(value)
                        .ok()
                        .map(|date| {
                            Duration::from_secs(
                                (date.timestamp() - chrono::Utc::now().timestamp()).max(0) as u64,
                            )
                        })
                })
        });

    let delay = requested.map_or(backoff, |requested| requested.max(backoff));
    // Never shorten a longer Retry-After requested by Apple's server.
    (delay <= MAX_RETRY_WAIT).then_some(delay)
}

struct DeveloperTokenRetry;

#[async_trait::async_trait]
impl Middleware for DeveloperTokenRetry {
    async fn handle(
        &self,
        request: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        // Only developer-token requests are eligible. Never retry account login,
        // password proof, 2FA, transport failures, or HTTP 429 responses.
        if !is_token_request(&request) {
            return next.run(request, extensions).await;
        }

        let mut retry = 0;
        loop {
            let Some(attempt) = request.try_clone() else {
                return next.run(request, extensions).await;
            };

            let response = next.clone().run(attempt, extensions).await?;
            if !is_temporary_status(response.status()) || retry >= MAX_TOKEN_RETRIES {
                return Ok(response);
            }

            let Some(delay) = retry_wait(response.headers(), retry) else {
                return Ok(response);
            };

            tracing::warn!(
                target: "apple_auth",
                status = response.status().as_u16(),
                retry = retry + 1,
                wait_seconds = delay.as_secs(),
                "Retrying Apple developer-token request"
            );

            drop(response);
            tokio::time::sleep(delay).await;
            retry += 1;
        }
    }
}
