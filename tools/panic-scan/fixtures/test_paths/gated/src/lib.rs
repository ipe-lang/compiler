//! Gates both test modules behind `#[cfg(test)]`; `contests` is production.

mod contests;
mod unit;

#[cfg(test)]
mod tests;
