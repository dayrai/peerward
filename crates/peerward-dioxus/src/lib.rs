//! Web-only Dioxus facade that deliberately has no Desktop or mobile `WebView`
//! dependency edge. Android renders the Web target in the system `WebView`.

pub use dioxus_config_macros as config_macros;
pub use dioxus_core;

#[cfg(feature = "router")]
pub use dioxus_router as router;

#[cfg(feature = "ssr")]
pub use dioxus_ssr as ssr;

/// The subset of the upstream Dioxus prelude used by Peerward applications.
pub mod prelude {
    pub use dioxus_core::{
        AnyhowContext, Attribute, Callback, CapturedError, Component, Element, ErrorBoundary,
        ErrorContext, Event, EventHandler, Fragment, HasAttributes, IntoDynNode, RenderError,
        Result, ScopeId, SuspenseBoundary, SuspenseContext, VNode, VirtualDom, consume_context,
        provide_context, spawn, suspend, try_consume_context, use_drop, use_hook,
    };
    #[allow(deprecated)]
    pub use dioxus_core_macro::{Props, component, rsx};
    pub use dioxus_elements::{
        Code, GlobalAttributesExtension, Key, Location, Modifiers, SvgAttributesExtension,
        events::*, extensions::*, global_attributes, keyboard_types, svg_attributes, traits::*,
    };
    pub use dioxus_hooks::*;
    pub use dioxus_html as dioxus_elements;
    pub use dioxus_signals::{self, *};
    pub use dioxus_stores::{self, GlobalStore, ReadStore, Store, WriteStore, store, use_store};

    #[cfg(feature = "router")]
    pub use dioxus_router::{
        GoBackButton, GoForwardButton, Link, NavigationTarget, Outlet, Routable, Router, hooks::*,
        navigator, use_navigator,
    };
}
