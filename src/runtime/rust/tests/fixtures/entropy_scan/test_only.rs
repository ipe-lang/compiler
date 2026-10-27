// A test-only draw, which the total ban still counts.
#[cfg(test)]
mod tests {
    fn t() {
        let _ = getrandom::getrandom;
    }
}
