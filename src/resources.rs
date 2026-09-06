//! Shared CPU and decoded-memory admission for content operations. Construct
//! once per installation runtime and inject into its capabilities.
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug)]
pub struct ContentResources {
    cpu: Arc<Semaphore>,
    memory: Arc<Semaphore>,
    memory_mib: u32,
}

pub struct ContentWorkPermit {
    _memory: OwnedSemaphorePermit,
    _cpu: OwnedSemaphorePermit,
}

impl Default for ContentResources {
    fn default() -> Self {
        let workers = std::thread::available_parallelism().map_or(2, |n| n.get().min(4));
        Self::new(workers, 256)
    }
}

impl ContentResources {
    pub async fn work(&self, bytes: u64) -> Result<ContentWorkPermit, crate::ContentError> {
        // Always reserve memory before CPU to avoid holding all workers while
        // waiting for memory owned by another operation.
        let memory = self.memory(bytes).await?;
        let cpu = self.cpu().await?;
        Ok(ContentWorkPermit {
            _memory: memory,
            _cpu: cpu,
        })
    }

    /// For dedicated native worker threads; creates no Tokio runtime or timers.
    pub fn blocking_work(&self, bytes: u64) -> Result<ContentWorkPermit, crate::ContentError> {
        futures::executor::block_on(self.work(bytes))
    }
    pub fn new(workers: usize, memory_mib: u32) -> Self {
        let memory_mib = memory_mib.clamp(1, 4096);
        Self {
            cpu: Arc::new(Semaphore::new(workers.clamp(1, 32))),
            memory: Arc::new(Semaphore::new(memory_mib as usize)),
            memory_mib,
        }
    }

    pub async fn cpu(&self) -> Result<OwnedSemaphorePermit, crate::ContentError> {
        self.cpu
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| crate::ContentError::Stopped)
    }

    pub async fn memory(&self, bytes: u64) -> Result<OwnedSemaphorePermit, crate::ContentError> {
        let units = bytes.div_ceil(1024 * 1024).max(1);
        if units > u64::from(self.memory_mib) {
            return Err(crate::ContentError::TooLarge {
                actual: bytes,
                maximum: u64::from(self.memory_mib) * 1024 * 1024,
            });
        }
        self.memory
            .clone()
            .acquire_many_owned(units as u32)
            .await
            .map_err(|_| crate::ContentError::Stopped)
    }

    pub fn shutdown(&self) {
        self.cpu.close();
        self.memory.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_and_shutdown_need_no_runtime() {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let resources = ContentResources::new(4, 128);
        let permit = resources.blocking_work(128 * 1024 * 1024).unwrap();
        drop(permit);
        resources.shutdown();
        assert!(resources.blocking_work(1).is_err());
    }

    #[tokio::test]
    async fn memory_is_bounded_and_released() {
        let resources = ContentResources::new(1, 2);
        assert!(resources.memory(3 * 1024 * 1024).await.is_err());
        let permit = resources.memory(2 * 1024 * 1024).await.unwrap();
        assert_eq!(resources.memory.available_permits(), 0);
        drop(permit);
        assert_eq!(resources.memory.available_permits(), 2);
    }
}
