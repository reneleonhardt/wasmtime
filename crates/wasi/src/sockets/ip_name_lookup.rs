use tracing::debug;

use crate::sockets::WasiSocketsCtx;
use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::Semaphore;

// Running OS calls keep their slots after guest cancellation or timeout.
static LOOKUP_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(16)));

#[derive(Debug, Clone)]
#[allow(unused, reason = "want to retain parity with the WIT enum")]
pub enum ErrorCode {
    AccessDenied,
    InvalidArgument,
    NameUnresolvable,
    TemporaryResolverFailure,
    PermanentResolverFailure,
    Other,
}

pub(crate) fn resolve_addresses(
    ctx: &WasiSocketsCtx,
    name: String,
) -> impl Future<Output = Result<Vec<IpAddr>, ErrorCode>> + Send + use<> {
    let allowed = ctx.allowed_network_uses.ip_name_lookup;
    let timeout = ctx
        .ip_name_lookup_timeout
        .unwrap_or(Duration::from_secs(30));

    async move {
        if !allowed {
            return Err(ErrorCode::PermanentResolverFailure);
        }

        // `url::Host::parse` serves us two purposes:
        // 1. validate the input is a valid domain name or IP,
        // 2. convert unicode domains to punycode.
        let domain = match url::Host::parse(&name) {
            Ok(url::Host::Domain(domain)) => domain,
            Ok(url::Host::Ipv4(addr)) => return Ok(vec![IpAddr::V4(addr)]),
            Ok(url::Host::Ipv6(addr)) => return Ok(vec![IpAddr::V6(addr)]),
            // `url::Host::parse` doesn't understand bare IPv6 addresses without [brackets]
            Err(_) if let Ok(addr) = std::net::Ipv6Addr::from_str(&name) => {
                return Ok(vec![IpAddr::V6(addr)]);
            }
            Err(_) => return Err(ErrorCode::InvalidArgument),
        };

        lookup(timeout, LOOKUP_SLOTS.clone(), move || {
            let addrs = (domain.as_str(), 0).to_socket_addrs().map_err(|e| {
                debug!("DNS resolution of `{}` failed because: {}", domain, e);
                // If/when we use `getaddrinfo` directly, map the error properly.
                ErrorCode::NameUnresolvable
            })?;
            Ok(addrs.map(|addr| addr.ip().to_canonical()).collect())
        })
        .await
    }
}

async fn lookup<T: Send + 'static>(
    timeout: Duration,
    slots: Arc<Semaphore>,
    work: impl FnOnce() -> Result<T, ErrorCode> + Send + 'static,
) -> Result<T, ErrorCode> {
    if timeout.is_zero() {
        return Err(ErrorCode::TemporaryResolverFailure);
    }
    tokio::time::timeout(timeout, async move {
        let permit = slots
            .try_acquire_owned()
            .map_err(|_| ErrorCode::TemporaryResolverFailure)?;
        crate::runtime::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
    })
    .await
    .unwrap_or(Err(ErrorCode::TemporaryResolverFailure))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::{Notify, oneshot};

    #[tokio::test]
    async fn permissions_literals_and_expired_deadline() {
        let mut ctx = WasiSocketsCtx::default();
        assert!(matches!(
            resolve_addresses(&ctx, "127.0.0.1".into()).await,
            Err(ErrorCode::PermanentResolverFailure)
        ));
        ctx.allowed_network_uses.ip_name_lookup = true;
        ctx.set_ip_name_lookup_timeout(Duration::ZERO);
        for literal in ["127.0.0.1", "::1", "[::1]"] {
            assert_eq!(
                resolve_addresses(&ctx, literal.into()).await.unwrap().len(),
                1
            );
        }
        assert!(matches!(
            resolve_addresses(&ctx, "invalid name".into()).await,
            Err(ErrorCode::InvalidArgument)
        ));
        assert!(matches!(
            resolve_addresses(&ctx, "localhost".into()).await,
            Err(ErrorCode::TemporaryResolverFailure)
        ));
        ctx.set_ip_name_lookup_timeout(Duration::from_secs(5));
        assert!(
            !resolve_addresses(&ctx, "localhost".into())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn timeout_configuration_is_captured_per_lookup() {
        let mut builder = crate::WasiCtxBuilder::new();
        builder
            .ip_name_lookup_timeout(Duration::ZERO)
            .allow_ip_name_lookup(true);
        let mut ctx = builder.build().sockets;
        let expired = resolve_addresses(&ctx, "localhost".into());
        ctx.set_ip_name_lookup_timeout(Duration::from_secs(5));
        assert!(matches!(
            expired.await,
            Err(ErrorCode::TemporaryResolverFailure)
        ));
        assert!(
            !resolve_addresses(&ctx, "localhost".into())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn cancellation_before_worker_start() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (release, wait) = oneshot::channel();
            let blocker = crate::runtime::spawn_blocking(move || wait.blocking_recv());
            let slots = Arc::new(Semaphore::new(1));
            let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let worker_ran = ran.clone();
            {
                let mut job =
                    std::pin::pin!(lookup(Duration::from_secs(60), slots.clone(), move || {
                        worker_ran.store(true, std::sync::atomic::Ordering::SeqCst);
                        Ok(())
                    }));
                assert!(crate::runtime::poll_noop(job.as_mut()).is_none());
                assert_eq!(slots.available_permits(), 0);
            }
            release.send(()).unwrap();
            blocker.await.unwrap();
            drop(
                tokio::time::timeout(Duration::from_secs(5), slots.acquire())
                    .await
                    .unwrap()
                    .unwrap(),
            );
            assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
        });
    }

    #[tokio::test]
    async fn deadline_and_cancellation_keep_worker_budget() {
        for cancel in [false, true] {
            let slots = Arc::new(Semaphore::new(1));
            let entered = Arc::new(Notify::new());
            let worker_entered = entered.clone();
            let (release, wait) = oneshot::channel();
            let job = tokio::spawn(lookup(
                if cancel {
                    Duration::from_secs(60)
                } else {
                    Duration::from_millis(50)
                },
                slots.clone(),
                move || {
                    worker_entered.notify_one();
                    wait.blocking_recv().unwrap();
                    Ok(42)
                },
            ));
            tokio::time::timeout(Duration::from_secs(5), entered.notified())
                .await
                .unwrap();
            if cancel {
                job.abort();
                assert!(
                    tokio::time::timeout(Duration::from_secs(5), job)
                        .await
                        .unwrap()
                        .unwrap_err()
                        .is_cancelled()
                );
            } else {
                assert!(matches!(
                    tokio::time::timeout(Duration::from_secs(5), job)
                        .await
                        .unwrap()
                        .unwrap(),
                    Err(ErrorCode::TemporaryResolverFailure)
                ));
            }
            assert_eq!(slots.available_permits(), 0);
            assert!(matches!(
                lookup(
                    Duration::from_secs(1),
                    slots.clone(),
                    || -> Result<(), ErrorCode> {
                        panic!("saturated lookups must not enqueue work")
                    }
                )
                .await,
                Err(ErrorCode::TemporaryResolverFailure)
            ));
            release.send(()).unwrap();
            drop(
                tokio::time::timeout(Duration::from_secs(5), slots.acquire())
                    .await
                    .unwrap()
                    .unwrap(),
            );
            assert_eq!(
                lookup(Duration::from_secs(1), slots.clone(), || Ok(7))
                    .await
                    .unwrap(),
                7
            );
            assert!(matches!(
                lookup(Duration::from_secs(1), slots, || {
                    Err::<(), _>(ErrorCode::NameUnresolvable)
                })
                .await,
                Err(ErrorCode::NameUnresolvable)
            ));
        }
    }
}
