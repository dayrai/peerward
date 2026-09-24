fn main() {
    dioxus_web::launch::launch_cfg(
        peerward_console::WebConsole,
        dioxus_web::Config::new().hydrate(true).rootname("main"),
    );
}
