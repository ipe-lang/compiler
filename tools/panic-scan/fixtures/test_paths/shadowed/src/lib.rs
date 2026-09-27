//! Declares its test module twice: the `cfg(test)` copy hides the production one.

#[cfg(test)]
mod tests;

#[cfg(not(test))]
pub mod tests;
