pub mod app;
pub mod cli;
pub mod client_api;
pub mod paths;
pub mod state;

pub fn run<I>(args: I) -> Result<String, String>
where
    I: IntoIterator<Item = String>,
{
    cli::run(args)
}

pub async fn run_main<I>(args: I) -> Result<Option<String>, String>
where
    I: IntoIterator<Item = String>,
{
    cli::run_main(args).await
}
