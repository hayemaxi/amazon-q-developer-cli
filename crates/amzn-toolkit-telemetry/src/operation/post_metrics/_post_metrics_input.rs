// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PostMetricsInput {
    #[allow(missing_docs)] // documentation missing in model
    pub aws_product: ::std::option::Option<crate::types::AwsProduct>,
    #[allow(missing_docs)] // documentation missing in model
    pub aws_product_version: ::std::option::Option<::std::string::String>,
    /// A valid UUID is expected, and this should be unique per-client and reused across API calls.
    pub client_id: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub os: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub os_architecture: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub os_version: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub parent_product: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub parent_product_version: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub metric_data: ::std::option::Option<::std::vec::Vec<crate::types::MetricDatum>>,
}
impl PostMetricsInput {
    #[allow(missing_docs)] // documentation missing in model
    pub fn aws_product(&self) -> ::std::option::Option<&crate::types::AwsProduct> {
        self.aws_product.as_ref()
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn aws_product_version(&self) -> ::std::option::Option<&str> {
        self.aws_product_version.as_deref()
    }

    /// A valid UUID is expected, and this should be unique per-client and reused across API calls.
    pub fn client_id(&self) -> ::std::option::Option<&str> {
        self.client_id.as_deref()
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn os(&self) -> ::std::option::Option<&str> {
        self.os.as_deref()
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn os_architecture(&self) -> ::std::option::Option<&str> {
        self.os_architecture.as_deref()
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn os_version(&self) -> ::std::option::Option<&str> {
        self.os_version.as_deref()
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn parent_product(&self) -> ::std::option::Option<&str> {
        self.parent_product.as_deref()
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn parent_product_version(&self) -> ::std::option::Option<&str> {
        self.parent_product_version.as_deref()
    }

    #[allow(missing_docs)] // documentation missing in model
    /// If no value was sent for this field, a default will be set. If you want to determine if no
    /// value was sent, use `.metric_data.is_none()`.
    pub fn metric_data(&self) -> &[crate::types::MetricDatum] {
        self.metric_data.as_deref().unwrap_or_default()
    }
}
impl PostMetricsInput {
    /// Creates a new builder-style object to manufacture
    /// [`PostMetricsInput`](crate::operation::post_metrics::PostMetricsInput).
    pub fn builder() -> crate::operation::post_metrics::builders::PostMetricsInputBuilder {
        crate::operation::post_metrics::builders::PostMetricsInputBuilder::default()
    }
}

/// A builder for [`PostMetricsInput`](crate::operation::post_metrics::PostMetricsInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct PostMetricsInputBuilder {
    pub(crate) aws_product: ::std::option::Option<crate::types::AwsProduct>,
    pub(crate) aws_product_version: ::std::option::Option<::std::string::String>,
    pub(crate) client_id: ::std::option::Option<::std::string::String>,
    pub(crate) os: ::std::option::Option<::std::string::String>,
    pub(crate) os_architecture: ::std::option::Option<::std::string::String>,
    pub(crate) os_version: ::std::option::Option<::std::string::String>,
    pub(crate) parent_product: ::std::option::Option<::std::string::String>,
    pub(crate) parent_product_version: ::std::option::Option<::std::string::String>,
    pub(crate) metric_data: ::std::option::Option<::std::vec::Vec<crate::types::MetricDatum>>,
}
impl PostMetricsInputBuilder {
    #[allow(missing_docs)] // documentation missing in model
    /// This field is required.
    pub fn aws_product(mut self, input: crate::types::AwsProduct) -> Self {
        self.aws_product = ::std::option::Option::Some(input);
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn set_aws_product(mut self, input: ::std::option::Option<crate::types::AwsProduct>) -> Self {
        self.aws_product = input;
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn get_aws_product(&self) -> &::std::option::Option<crate::types::AwsProduct> {
        &self.aws_product
    }

    #[allow(missing_docs)] // documentation missing in model
    /// This field is required.
    pub fn aws_product_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_product_version = ::std::option::Option::Some(input.into());
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn set_aws_product_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_product_version = input;
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn get_aws_product_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_product_version
    }

    /// A valid UUID is expected, and this should be unique per-client and reused across API calls.
    /// This field is required.
    pub fn client_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_id = ::std::option::Option::Some(input.into());
        self
    }

    /// A valid UUID is expected, and this should be unique per-client and reused across API calls.
    pub fn set_client_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_id = input;
        self
    }

    /// A valid UUID is expected, and this should be unique per-client and reused across API calls.
    pub fn get_client_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_id
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn os(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.os = ::std::option::Option::Some(input.into());
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn set_os(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.os = input;
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn get_os(&self) -> &::std::option::Option<::std::string::String> {
        &self.os
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn os_architecture(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.os_architecture = ::std::option::Option::Some(input.into());
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn set_os_architecture(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.os_architecture = input;
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn get_os_architecture(&self) -> &::std::option::Option<::std::string::String> {
        &self.os_architecture
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn os_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.os_version = ::std::option::Option::Some(input.into());
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn set_os_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.os_version = input;
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn get_os_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.os_version
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn parent_product(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_product = ::std::option::Option::Some(input.into());
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn set_parent_product(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_product = input;
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn get_parent_product(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_product
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn parent_product_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_product_version = ::std::option::Option::Some(input.into());
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn set_parent_product_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_product_version = input;
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn get_parent_product_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_product_version
    }

    /// Appends an item to `metric_data`.
    ///
    /// To override the contents of this collection use [`set_metric_data`](Self::set_metric_data).
    pub fn metric_data(mut self, input: crate::types::MetricDatum) -> Self {
        let mut v = self.metric_data.unwrap_or_default();
        v.push(input);
        self.metric_data = ::std::option::Option::Some(v);
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn set_metric_data(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MetricDatum>>) -> Self {
        self.metric_data = input;
        self
    }

    #[allow(missing_docs)] // documentation missing in model
    pub fn get_metric_data(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MetricDatum>> {
        &self.metric_data
    }

    /// Consumes the builder and constructs a
    /// [`PostMetricsInput`](crate::operation::post_metrics::PostMetricsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::post_metrics::PostMetricsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::post_metrics::PostMetricsInput {
            aws_product: self.aws_product,
            aws_product_version: self.aws_product_version,
            client_id: self.client_id,
            os: self.os,
            os_architecture: self.os_architecture,
            os_version: self.os_version,
            parent_product: self.parent_product,
            parent_product_version: self.parent_product_version,
            metric_data: self.metric_data,
        })
    }
}
