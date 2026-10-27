// A uuid time-ordered generator, direct and through an alias.
use uuid::Uuid as Id;
fn mint() {
    let _ = Uuid::now_v7();
    let _ = Id::now_v7();
}
