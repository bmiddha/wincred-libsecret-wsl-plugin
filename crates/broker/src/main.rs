use std::io;

#[cfg(any(windows, test))]
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::error;
#[cfg(windows)]
use tracing::warn;
#[cfg(any(windows, test))]
use wincred_libsecret_broker::Broker;
#[cfg(test)]
use wincred_libsecret_protocol::Operation;
#[cfg(any(windows, test))]
use wincred_libsecret_protocol::{
    BrokerError, Capability, CapabilitySet, Envelope, ErrorCode, Hello, HelloAck, ProtocolError,
    Request, Response, VersionRange, negotiate, read_frame, write_frame,
};

#[cfg(windows)]
use wincred_libsecret_broker::WinCredBackend;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .with_writer(io::stderr)
        .init();

    #[cfg(windows)]
    if let Err(error) = run().await {
        error!(event = "broker_stopped", error = %error, "broker stopped");
    }

    #[cfg(not(windows))]
    error!(
        event = "unsupported_platform",
        "the WinCred broker requires Windows"
    );
}

#[cfg(windows)]
async fn run() -> Result<(), ProtocolError> {
    let broker = Broker::new(WinCredBackend::new());
    if let Err(error) = broker.reconcile() {
        warn!(event = "startup_reconcile_failed", code = ?error.code, "startup reconciliation deferred");
    }

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    serve(stdin, stdout, &broker).await
}

#[cfg(any(windows, test))]
async fn serve<R, W, B>(
    mut reader: R,
    mut writer: W,
    broker: &Broker<B>,
) -> Result<(), ProtocolError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    B: wincred_libsecret_broker::VaultBackend,
{
    let hello: Envelope<Hello> = read_frame(&mut reader).await?;
    hello.validate_version()?;
    let capabilities: CapabilitySet = [
        Capability::BinarySecrets,
        Capability::Collections,
        Capability::Aliases,
        Capability::GenerationCommits,
        Capability::Reconciliation,
        Capability::AtomicItemMutations,
    ]
    .into_iter()
    .collect();
    let acknowledgement: HelloAck =
        negotiate(&hello.payload, VersionRange::current(), &capabilities)?;
    write_frame(&mut writer, &Envelope::current(acknowledgement.clone())).await?;

    loop {
        let envelope: Envelope<Request> = match read_frame(&mut reader).await {
            Ok(envelope) => envelope,
            Err(ProtocolError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let request_id = envelope.payload.request_id;
        let result = if envelope.version == acknowledgement.version {
            broker.execute(envelope.payload.operation)
        } else {
            Err(BrokerError::new(
                ErrorCode::UnsupportedVersion,
                "request protocol version was not negotiated",
            ))
        };
        write_frame(
            &mut writer,
            &Envelope::current(Response { request_id, result }),
        )
        .await?;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use tokio::io::{AsyncWriteExt, duplex};
    use uuid::Uuid;
    use wincred_libsecret_broker::InMemoryBackend;
    use wincred_libsecret_protocol::{PROTOCOL_VERSION, ResponseBody};

    use super::*;

    #[tokio::test]
    async fn serves_handshake_and_ping_on_framed_stdio() {
        let (mut client, server) = duplex(4096);
        let broker = Broker::new(InMemoryBackend::new());
        let task = tokio::spawn(async move {
            let (input, output) = tokio::io::split(server);
            serve(input, output, &broker).await.unwrap();
        });
        write_frame(
            &mut client,
            &Envelope::current(Hello {
                versions: VersionRange::current(),
                capabilities: BTreeSet::new(),
            }),
        )
        .await
        .unwrap();
        let ack: Envelope<HelloAck> = read_frame(&mut client).await.unwrap();
        assert_eq!(ack.payload.version, PROTOCOL_VERSION);
        write_frame(
            &mut client,
            &Envelope::current(Request {
                request_id: 4,
                operation: Operation::Ping,
            }),
        )
        .await
        .unwrap();
        let response: Envelope<Response> = read_frame(&mut client).await.unwrap();
        assert_eq!(response.payload.request_id, 4);
        assert_eq!(response.payload.result.unwrap(), ResponseBody::Pong);
        drop(client);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn returns_typed_error_for_bad_request_version() {
        let (mut client, server) = duplex(4096);
        let broker = Broker::new(InMemoryBackend::new());
        let task = tokio::spawn(async move {
            let (input, output) = tokio::io::split(server);
            serve(input, output, &broker).await.unwrap();
        });
        write_frame(
            &mut client,
            &Envelope::current(Hello {
                versions: VersionRange::current(),
                capabilities: BTreeSet::new(),
            }),
        )
        .await
        .unwrap();
        let _: Envelope<HelloAck> = read_frame(&mut client).await.unwrap();
        write_frame(
            &mut client,
            &Envelope {
                version: PROTOCOL_VERSION + 1,
                payload: Request {
                    request_id: 9,
                    operation: Operation::GetCollection {
                        collection_id: Uuid::new_v4(),
                    },
                },
            },
        )
        .await
        .unwrap();
        let response: Envelope<Response> = read_frame(&mut client).await.unwrap();
        assert_eq!(
            response.payload.result.unwrap_err().code,
            ErrorCode::UnsupportedVersion
        );
        drop(client);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_request_frame_ends_without_a_panic() {
        let (mut client, server) = duplex(4096);
        let broker = Broker::new(InMemoryBackend::new());
        let task = tokio::spawn(async move {
            let (input, output) = tokio::io::split(server);
            serve(input, output, &broker).await
        });
        write_frame(
            &mut client,
            &Envelope::current(Hello {
                versions: VersionRange::current(),
                capabilities: BTreeSet::new(),
            }),
        )
        .await
        .unwrap();
        let _: Envelope<HelloAck> = read_frame(&mut client).await.unwrap();
        client.write_u32(1).await.unwrap();
        client.write_u8(255).await.unwrap();
        drop(client);

        assert!(matches!(task.await.unwrap(), Err(ProtocolError::Decode(_))));
    }
}
