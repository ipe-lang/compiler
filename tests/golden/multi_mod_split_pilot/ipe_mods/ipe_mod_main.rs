use crate::*;

pub(crate) fn main_summary(count: i64) -> String {
    let _ipe_recursion_guard = crate::recursion_guard();
    format!(
        "{}{}",
        crate::lib_label(LibStatus::Seeded),
        format!("{}{}", ":".to_string(), string_from_int(count))
    )
}

pub(crate) fn ipe_main() -> IpeTask<()> {
    let _ipe_recursion_guard = crate::recursion_guard();
    task_and_then(
        crate::lib_seed_and_count(),
        Box::new(move |count: i64| -> IpeTask<()> { io_println(crate::main_summary(count)) }),
    )
}
