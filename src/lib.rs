//! Shared content plane for clipboard blobs, nearby files, remote files and
//! print documents. The crate owns integrity, bounds and one-use tickets; it
//! deliberately has no knowledge of QUIC or any UI.

use std::{fmt, str::FromStr};

use arcrelay_peer::DeviceId;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod resources;
pub use resources::{ContentResources, ContentWorkPermit};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContentId(String);

impl ContentId {
    pub fn from_sha256(digest: &[u8; 32]) -> Self {
        Self(hex(digest))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ContentId {
    type Err = ContentError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 || !value.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(ContentError::InvalidId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentDescriptor {
    pub id: ContentId,
    pub name: String,
    pub media_type: String,
    pub length: u64,
    pub sha256: [u8; 32],
}

impl ContentDescriptor {
    pub fn new(
        name: impl Into<String>,
        media_type: impl Into<String>,
        length: u64,
        sha256: [u8; 32],
    ) -> Self {
        Self {
            id: ContentId::from_sha256(&sha256),
            name: name.into(),
            media_type: media_type.into(),
            length,
            sha256,
        }
    }

    pub fn validate(&self, maximum: u64) -> Result<(), ContentError> {
        if self.length > maximum {
            return Err(ContentError::TooLarge {
                actual: self.length,
                maximum,
            });
        }
        if self.id != ContentId::from_sha256(&self.sha256) {
            return Err(ContentError::InvalidId);
        }
        if self.name.is_empty() || self.name.len() > 512 || self.media_type.len() > 255 {
            return Err(ContentError::InvalidMetadata);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentTicket {
    pub descriptor: ContentDescriptor,
    pub peer_id: DeviceId,
    pub purpose: String,
    pub expires_at_ms: i64,
    pub token: [u8; 32],
}

/// Issues capability-scoped, peer-bound tickets. Applications must consume a
/// token atomically in their repository before accepting the content stream.
pub struct TicketIssuer {
    secret: [u8; 32],
}

impl TicketIssuer {
    pub fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    pub fn issue(
        &self,
        descriptor: ContentDescriptor,
        peer_id: DeviceId,
        purpose: impl Into<String>,
        expires_at_ms: i64,
    ) -> ContentTicket {
        let purpose = purpose.into();
        let token = self.sign(&descriptor, &peer_id, &purpose, expires_at_ms);
        ContentTicket {
            descriptor,
            peer_id,
            purpose,
            expires_at_ms,
            token,
        }
    }

    pub fn verify(&self, ticket: &ContentTicket, now_ms: i64) -> Result<(), ContentError> {
        if ticket.expires_at_ms < now_ms {
            return Err(ContentError::Expired);
        }
        let expected = self.sign(
            &ticket.descriptor,
            &ticket.peer_id,
            &ticket.purpose,
            ticket.expires_at_ms,
        );
        if expected.ct_eq(&ticket.token).unwrap_u8() != 1 {
            return Err(ContentError::InvalidTicket);
        }
        Ok(())
    }

    fn sign(
        &self,
        descriptor: &ContentDescriptor,
        peer_id: &DeviceId,
        purpose: &str,
        expires_at_ms: i64,
    ) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts 32-byte keys");
        update_field(&mut mac, descriptor.id.as_str().as_bytes());
        update_field(&mut mac, peer_id.as_str().as_bytes());
        update_field(&mut mac, purpose.as_bytes());
        mac.update(&descriptor.length.to_be_bytes());
        mac.update(&descriptor.sha256);
        mac.update(&expires_at_ms.to_be_bytes());
        mac.finalize().into_bytes().into()
    }
}

fn update_field(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

/// Copies exactly the declared number of bytes while enforcing the maximum and
/// validating SHA-256 before success is reported.
pub async fn receive_verified<R, W>(
    reader: &mut R,
    writer: &mut W,
    descriptor: &ContentDescriptor,
    maximum: u64,
) -> Result<(), ContentError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    descriptor.validate(maximum)?;
    let mut remaining = descriptor.length;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = reader.read(&mut buffer[..wanted]).await?;
        if read == 0 {
            return Err(ContentError::Truncated {
                expected: descriptor.length,
                actual: descriptor.length - remaining,
            });
        }
        writer.write_all(&buffer[..read]).await?;
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    writer.flush().await?;
    let actual: [u8; 32] = digest.finalize().into();
    if actual.ct_eq(&descriptor.sha256).unwrap_u8() != 1 {
        return Err(ContentError::Integrity);
    }
    Ok(())
}

pub async fn describe<R>(
    reader: &mut R,
    name: impl Into<String>,
    media_type: impl Into<String>,
    maximum: u64,
) -> Result<(ContentDescriptor, Vec<u8>), ContentError>
where
    R: AsyncRead + Unpin,
{
    let capacity = usize::try_from(maximum.min(1024 * 1024)).unwrap_or(1024 * 1024);
    let mut bytes = Vec::with_capacity(capacity);
    reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > maximum {
        return Err(ContentError::TooLarge {
            actual: bytes.len() as u64,
            maximum,
        });
    }
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    Ok((
        ContentDescriptor::new(name, media_type, bytes.len() as u64, digest),
        bytes,
    ))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, thiserror::Error)]
pub enum ContentError {
    #[error("content runtime is stopping")]
    Stopped,
    #[error("invalid content identifier")]
    InvalidId,
    #[error("invalid content metadata")]
    InvalidMetadata,
    #[error("content is too large: {actual} bytes (maximum {maximum})")]
    TooLarge { actual: u64, maximum: u64 },
    #[error("content stream ended early: expected {expected}, received {actual}")]
    Truncated { expected: u64, actual: u64 },
    #[error("content integrity verification failed")]
    Integrity,
    #[error("content ticket is invalid")]
    InvalidTicket,
    #[error("content ticket expired")]
    Expired,
    #[error("content I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

impl ContentError {
    /// Stable machine-readable category for protocol adapters.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidId | Self::InvalidMetadata | Self::InvalidTicket => {
                "content.invalid_argument"
            }
            Self::TooLarge { .. } => "content.resource_exhausted",
            Self::Truncated { .. } | Self::Io(_) | Self::Stopped => "content.unavailable",
            Self::Integrity => "content.integrity",
            Self::Expired => "content.expired",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arcrelay_peer::DevicePublicKey;

    #[tokio::test]
    async fn verifies_content_and_rejects_corruption() {
        let bytes = b"one content plane";
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let descriptor =
            ContentDescriptor::new("note.txt", "text/plain", bytes.len() as u64, digest);
        let mut input = &bytes[..];
        let mut output = Vec::new();
        receive_verified(&mut input, &mut output, &descriptor, 1024)
            .await
            .unwrap();
        assert_eq!(output, bytes);
    }

    #[test]
    fn ticket_is_bound_to_peer_and_purpose() {
        let digest = [7_u8; 32];
        let descriptor = ContentDescriptor::new("x", "application/octet-stream", 1, digest);
        let peer = DeviceId::from_public_key(&DevicePublicKey::from_bytes(vec![9; 32]).unwrap());
        let issuer = TicketIssuer::new([3; 32]);
        let ticket = issuer.issue(descriptor, peer, "print.document", 100);
        issuer.verify(&ticket, 99).unwrap();
        assert!(matches!(
            issuer.verify(&ticket, 101),
            Err(ContentError::Expired)
        ));
    }
}
