use anyhow::{Context, Result};

pub async fn run<T, F>(name: &str, task: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let task_name = name.to_owned();
    std::thread::Builder::new()
        .name(task_name.clone())
        .spawn(move || {
            let _ = sender.send(task());
        })
        .with_context(|| format!("start {task_name}"))?;
    receiver.await.context("cpu task exited")?
}
