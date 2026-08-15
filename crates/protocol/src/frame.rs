use std::io::Cursor;

use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::ProtocolError;

/// Maximum encoded CBOR payload accepted from either side of the bridge.
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Reads one big-endian length-prefixed CBOR frame.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let length = reader.read_u32().await? as usize;
    if length == 0 {
        return Err(ProtocolError::EmptyFrame);
    }
    if length > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            actual: length,
            maximum: MAX_FRAME_SIZE,
        });
    }

    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;

    let mut cursor = Cursor::new(payload);
    let value = ciborium::de::from_reader(&mut cursor)
        .map_err(|error| ProtocolError::Decode(error.to_string()))?;
    let consumed = usize::try_from(cursor.position())
        .map_err(|error| ProtocolError::Decode(error.to_string()))?;
    if consumed != length {
        return Err(ProtocolError::TrailingBytes(length - consumed));
    }

    Ok(value)
}

/// Writes one big-endian length-prefixed CBOR frame.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut payload = Vec::new();
    ciborium::ser::into_writer(value, &mut payload)
        .map_err(|error| ProtocolError::Encode(error.to_string()))?;

    if payload.is_empty() {
        return Err(ProtocolError::EmptyFrame);
    }
    if payload.len() > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            actual: payload.len(),
            maximum: MAX_FRAME_SIZE,
        });
    }

    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge {
        actual: payload.len(),
        maximum: MAX_FRAME_SIZE,
    })?;
    writer.write_u32(length).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_bytes::ByteBuf;
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct Fixture {
        value: String,
    }

    #[tokio::test]
    async fn frame_round_trips() {
        let (mut client, mut server) = duplex(1024);
        let expected = Fixture {
            value: "hello".to_owned(),
        };

        write_frame(&mut client, &expected).await.unwrap();
        let actual: Fixture = read_frame(&mut server).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn rejects_empty_frames() {
        let (mut client, mut server) = duplex(16);
        client.write_u32(0).await.unwrap();

        assert!(matches!(
            read_frame::<_, Fixture>(&mut server).await,
            Err(ProtocolError::EmptyFrame)
        ));
    }

    #[tokio::test]
    async fn rejects_oversized_frames_before_allocating() {
        let (mut client, mut server) = duplex(16);
        client
            .write_u32(u32::try_from(MAX_FRAME_SIZE + 1).unwrap())
            .await
            .unwrap();

        assert!(matches!(
            read_frame::<_, Fixture>(&mut server).await,
            Err(ProtocolError::FrameTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_trailing_cbor_data() {
        let mut payload = Vec::new();
        ciborium::ser::into_writer(
            &Fixture {
                value: "hello".to_owned(),
            },
            &mut payload,
        )
        .unwrap();
        payload.push(0);

        let (mut client, mut server) = duplex(1024);
        client
            .write_u32(u32::try_from(payload.len()).unwrap())
            .await
            .unwrap();
        client.write_all(&payload).await.unwrap();

        assert!(matches!(
            read_frame::<_, Fixture>(&mut server).await,
            Err(ProtocolError::TrailingBytes(1))
        ));
    }

    #[tokio::test]
    async fn reads_a_frame_delivered_in_fragments() {
        let expected = Fixture {
            value: "fragmented unicode 🔐".to_owned(),
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&expected, &mut payload).unwrap();
        let mut frame = (u32::try_from(payload.len()).unwrap())
            .to_be_bytes()
            .to_vec();
        frame.extend(payload);

        let (mut client, mut server) = duplex(32);
        let receive = tokio::spawn(async move { read_frame::<_, Fixture>(&mut server).await });
        for chunk in frame.chunks(2) {
            client.write_all(chunk).await.unwrap();
        }
        assert_eq!(receive.await.unwrap().unwrap(), expected);
    }

    #[tokio::test]
    async fn reports_truncated_and_malformed_payloads() {
        let (mut client, mut server) = duplex(32);
        client.write_u32(4).await.unwrap();
        client.write_all(&[0xA1, 0x65]).await.unwrap();
        drop(client);
        assert!(matches!(
            read_frame::<_, Fixture>(&mut server).await,
            Err(ProtocolError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof
        ));

        let (mut client, mut server) = duplex(32);
        client.write_u32(1).await.unwrap();
        client.write_u8(0xFF).await.unwrap();
        assert!(matches!(
            read_frame::<_, Fixture>(&mut server).await,
            Err(ProtocolError::Decode(_))
        ));
    }

    #[tokio::test]
    async fn accepts_the_exact_maximum_encoded_payload() {
        // CBOR byte strings with this length have a five-byte header.
        let expected = ByteBuf::from(vec![0x5A; MAX_FRAME_SIZE - 5]);
        let (mut client, mut server) = duplex(MAX_FRAME_SIZE + 4);
        write_frame(&mut client, &expected).await.unwrap();
        let actual: ByteBuf = read_frame(&mut server).await.unwrap();
        assert_eq!(actual.len(), expected.len());
        assert!(actual.iter().all(|byte| *byte == 0x5A));
    }
}
