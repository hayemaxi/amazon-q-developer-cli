// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_previous_editor_state_metadata(
    object: &mut ::aws_smithy_json::serialize::JsonObjectWriter,
    input: &crate::types::PreviousEditorStateMetadata,
) -> ::std::result::Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    {
        object.key("timeOffset").number(
            #[allow(clippy::useless_conversion)]
            ::aws_smithy_types::Number::NegInt((input.time_offset).into()),
        );
    }
    Ok(())
}
