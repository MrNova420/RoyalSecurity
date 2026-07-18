pub mod router;
pub mod handlers;
pub mod middleware;
pub mod types;

pub use router::create_router;
pub use router::start_server;

#[cfg(test)]
mod tests;
