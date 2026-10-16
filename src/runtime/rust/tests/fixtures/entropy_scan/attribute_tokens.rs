// A mint inside an attribute macro's arguments.
#[tracing::instrument(fields(id = %uuid::Uuid::new_v4()))]
fn handle() {}
