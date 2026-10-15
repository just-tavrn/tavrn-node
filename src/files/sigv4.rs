// SPDX-License-Identifier: AGPL-3.0-only
//! AWS Signature Version 4 for S3-compatible object stores (files channels).
//!
//! Hand-written instead of an SDK: the node only needs PUT, GET, HEAD and DELETE of single objects. Payloads
//! are not hashed (`UNSIGNED-PAYLOAD`, streams of unknown content); everything else follows the AWS
//! specification and is tested against the examples of the AWS documentation.

use crate::util::percent_decode;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::Url;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// `x-amz-content-sha256` of a streamed payload.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
/// SHA-256 of the empty payload.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC accepts keys of any length.
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).unwrap_or_else(|_| unreachable!("HMAC takes any key"));
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// URI encoding of the specification: everything but `A-Z a-z 0-9 - . _ ~` (and `/` in paths) as `%XX`.
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Credentials and scope of a signer.
pub struct Signer<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

impl Signer<'_> {
    /// The canonical request (exposed for tests).
    pub fn canonical_request(method: &str, url: &Url, headers: &[(String, String)], payload_hash: &str) -> String {
        // The path as sent (S3 does not normalise it); decoded and encoded again so that it is encoded once.
        let path = percent_decode(url.path());
        let canonical_uri = if path.is_empty() { "/".to_string() } else { uri_encode(&path, true) };
        let mut query: Vec<(String, String)> =
            url.query_pairs().map(|(k, v)| (uri_encode(&k, false), uri_encode(&v, false))).collect();
        query.sort();
        let canonical_query = query.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
        let mut sorted: Vec<(String, String)> =
            headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string())).collect();
        sorted.sort();
        let canonical_headers: String = sorted.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let signed = sorted.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
        format!("{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed}\n{payload_hash}")
    }

    /// The `Authorization` header for a request with `headers` (every header to sign, including `host`,
    /// `x-amz-content-sha256` and `x-amz-date`) at `amz_date` (`YYYYMMDDTHHMMSSZ`).
    pub fn authorization(
        &self,
        method: &str,
        url: &Url,
        headers: &[(String, String)],
        payload_hash: &str,
        amz_date: &str,
    ) -> String {
        let date = &amz_date[..8.min(amz_date.len())];
        let scope = format!("{date}/{}/{}/aws4_request", self.region, self.service);
        let canonical = Self::canonical_request(method, url, headers, payload_hash);
        let string_to_sign =
            format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
        let k_date = hmac(format!("AWS4{}", self.secret_key).as_bytes(), date.as_bytes());
        let k_region = hmac(&k_date, self.region.as_bytes());
        let k_service = hmac(&k_region, self.service.as_bytes());
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex(&hmac(&k_signing, string_to_sign.as_bytes()));
        let mut names: Vec<String> = headers.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
        names.sort();
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={}, Signature={signature}",
            self.access_key,
            names.join(";")
        )
    }
}

/// The `Host` header value of a URL (port only when it is not the scheme's default).
pub fn host_header(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const ACCESS: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn signer() -> Signer<'static> {
        Signer { access_key: ACCESS, secret_key: SECRET, region: "us-east-1", service: "s3" }
    }

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// AWS documentation, "Signature Calculations for the Authorization Header: Transferring Payload in a
    /// Single Chunk", example "GET Object".
    #[test]
    fn aws_example_get_object() {
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
        let headers = h(&[
            ("Host", "examplebucket.s3.amazonaws.com"),
            ("Range", "bytes=0-9"),
            ("x-amz-content-sha256", EMPTY_SHA256),
            ("x-amz-date", "20130524T000000Z"),
        ]);
        let canonical = Signer::canonical_request("GET", &url, &headers, EMPTY_SHA256);
        assert_eq!(
            hex(&Sha256::digest(canonical.as_bytes())),
            "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
        );
        let auth = signer().authorization("GET", &url, &headers, EMPTY_SHA256, "20130524T000000Z");
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// Same source, example "GET Bucket (List Objects)": the query string is sorted and encoded.
    #[test]
    fn aws_example_list_objects() {
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J").unwrap();
        let headers = h(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", EMPTY_SHA256),
            ("x-amz-date", "20130524T000000Z"),
        ]);
        let auth = signer().authorization("GET", &url, &headers, EMPTY_SHA256, "20130524T000000Z");
        assert!(auth.ends_with("Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"), "{auth}");
    }

    #[test]
    fn encoding_follows_the_specification() {
        assert_eq!(uri_encode("a b/c~d", true), "a%20b/c~d");
        assert_eq!(uri_encode("a b/c", false), "a%20b%2Fc");
        assert_eq!(uri_encode("ä", false), "%C3%A4");
        let url = Url::parse("http://127.0.0.1:9000/bucket/key").unwrap();
        assert_eq!(host_header(&url), "127.0.0.1:9000");
        assert_eq!(host_header(&Url::parse("https://s3.example/b").unwrap()), "s3.example");
    }
}
