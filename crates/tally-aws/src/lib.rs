//! AWS implementations of DMARC Tally's platform-independent capabilities.

pub mod auth_store;
pub mod dynamo_repository;
pub mod dynamodb;
pub mod entropy;
pub mod s3;
pub mod ses_email;
