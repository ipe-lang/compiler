// The uuid clock read.
fn stamp(context: uuid::NoContext) {
    let _ = uuid::Timestamp::now(context);
}
