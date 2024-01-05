use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHashString, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use futures::FutureExt;
use gloo::storage::{LocalStorage, Storage};
use sha2::{digest, Sha256};
use std::time::Duration;
use strum::{EnumMessage, IntoEnumIterator};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Event, HtmlInputElement, HtmlSelectElement};
use yew::TargetCast;

fn main() {
    yew::Renderer::<App>::new().render();
}

enum Message {
    Password(String),
    HashExpected(Option<PasswordHashString>),
    Algorithm(Algorithm),
    Salt(String),
}

#[derive(
    Clone, Copy, PartialEq, strum::Display, strum::EnumIter, strum::EnumMessage, strum::EnumString,
)]
enum Algorithm {
    #[strum(message = "argon2id (256 bits)")]
    Argon2id256,
    #[strum(message = "s2k (SHA256)")]
    S2kSha256,
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::Argon2id256
    }
}

struct App {
    argon2: Argon2<'static>,
    password: String,
    password_validation: Option<Result<(), String>>,
    hash_actual: String,
    hash_expected: Option<PasswordHashString>,
    algorithm: Algorithm,
    salt: String,
    salt_validation: Result<(), String>,
    key: Option<String>,
}

impl yew::Component for App {
    type Message = Message;
    type Properties = ();

    fn create(_: &yew::Context<Self>) -> Self {
        let mut s = Self {
            argon2: Argon2::default(),
            password: String::new(),
            password_validation: None,
            hash_actual: String::new(),
            hash_expected: None,
            algorithm: Algorithm::default(),
            salt: String::new(),
            salt_validation: Ok(()),
            key: None,
        };
        s.update_password_validation();
        s.update_hash_actual();
        s.update_key();
        s
    }

    fn update(&mut self, _: &yew::Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::Password(value) => {
                self.password = value;
                self.update_password_validation();
                self.update_hash_actual();
                self.update_key();
            }
            Message::HashExpected(value) => {
                self.hash_expected = value;
                self.update_password_validation();
            }
            Message::Algorithm(value) => {
                self.algorithm = value;
                self.update_key();
            }
            Message::Salt(value) => {
                self.salt = value;
                self.update_key();
            }
        }
        true
    }

    fn view(&self, ctx: &yew::Context<Self>) -> yew::Html {
        yew::html! {
            <main class="card">
            <section class="card-body">
            <PasswordInput onchange={ctx.link().callback(Message::Password)} validation={self.password_validation.clone()} />
            <HashActualOutput value={self.hash_actual.clone()} />
            <HashExpectedInput onchange={ctx.link().callback(Message::HashExpected)} />
            </section>
            <section class="card-body">
            <AlgorithmInput onchange={ctx.link().callback(Message::Algorithm)} />
            <SaltInput onchange={ctx.link().callback(Message::Salt)} validation={self.salt_validation.clone()} />
            <KeyOutput value={self.key.clone()} />
            </section>
            </main>
        }
    }
}

impl App {
    fn update_password_validation(&mut self) {
        self.password_validation = self.hash_expected.as_ref().map(|hash_expected| {
            self.argon2
                .verify_password(self.password.as_bytes(), &hash_expected.password_hash())
                .map_err(|e| e.to_string())
        });
    }

    fn update_hash_actual(&mut self) {
        self.hash_actual = self
            .argon2
            .hash_password(self.password.as_bytes(), &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
    }

    fn update_key(&mut self) {
        match self.algorithm {
            Algorithm::Argon2id256 => {
                let mut key = [0u8; 32];
                match self.argon2.hash_password_into(
                    self.password.as_bytes(),
                    self.salt.as_bytes(),
                    &mut key,
                ) {
                    Ok(_) => {
                        self.key = Some(base64::encode(key));
                        self.salt_validation = Ok(());
                    }
                    Err(e @ argon2::Error::SaltTooShort | e @ argon2::Error::SaltTooLong) => {
                        self.key = None;
                        self.salt_validation = Err(e.to_string());
                    }
                    _ => unimplemented!(),
                }
            }
            Algorithm::S2kSha256 => {
                self.key = Some(base64::encode(s2k::<Sha256>(
                    self.salt.as_bytes(),
                    self.password.as_bytes(),
                    65536,
                )));
                self.salt_validation = Ok(());
            }
        };
    }
}

#[derive(PartialEq, yew::Properties)]
struct PasswordInputProps {
    onchange: yew::Callback<String>,
    validation: Option<Result<(), String>>,
}

#[yew::function_component]
fn PasswordInput(props: &PasswordInputProps) -> yew::Html {
    let value = yew::use_state(String::new);
    let onchange = {
        let setter = value.setter();
        let callback = props.onchange.clone();
        move |event: Event| {
            let value = event.target_dyn_into::<HtmlInputElement>().unwrap().value();
            setter.set(value.clone());
            callback.emit(value);
        }
    };
    let class_a = [
        Some("input-group"),
        props.validation.as_ref().map(|_| "has-validation"),
    ]
    .into_iter()
    .collect::<yew::Classes>();
    let class_b = [
        Some("form-control"),
        match &props.validation {
            Some(Ok(_)) => Some("is-valid"),
            Some(Err(_)) => Some("is-invalid"),
            None => None,
        },
    ]
    .into_iter()
    .collect::<yew::Classes>();
    yew::html! {
        <div class={class_a}>
        <label for="password" class={yew::classes!("input-group-prepend", "input-group-text")}>{"Password"}</label>
        <input type="password" id="password" class={class_b} value={(*value).clone()} onchange={onchange} />
        if let Some(Err(e)) = &props.validation {
            <div class={yew::classes!("invalid-feedback")}>{e.to_string()}</div>
        }
        </div>
    }
}

#[derive(PartialEq, yew::Properties)]
struct HashActualOutputProps {
    value: String,
}

#[yew::function_component]
fn HashActualOutput(props: &HashActualOutputProps) -> yew::Html {
    let onclick = {
        let value = props.value.clone();
        move |_| {
            let _ = LocalStorage::set("hash", &value);
        }
    };
    yew::html! {
        <div class="input-group">
        <label for="hash-actual" class={yew::classes!("input-group-prepend", "input-group-text")}>{"Hash (actual)"}</label>
        <input type="text" id="hash-actual" class={yew::classes!("form-control")} value={props.value.clone()} readonly=true />
        <div class="input-group-append">
        <button type="button" class={yew::classes!("btn", "btn-outline-secondary")} onclick={onclick}>
        <i class="bi bi-file-earmark-arrow-up" />
        </button>
        </div>
        </div>
    }
}

#[derive(PartialEq, yew::Properties)]
struct HashExpectedInputProps {
    onchange: yew::Callback<Option<PasswordHashString>>,
}

#[yew::function_component]
fn HashExpectedInput(props: &HashExpectedInputProps) -> yew::Html {
    let value = yew::use_state(String::new);
    let validation = yew::use_state(|| PasswordHashString::new("").map(|_| ()));
    let onchange = {
        let setter = value.setter();
        let validation_setter = validation.setter();
        let callback = props.onchange.clone();
        move |event: Event| {
            let value = event.target_dyn_into::<HtmlInputElement>().unwrap().value();
            setter.set(value.clone());
            match PasswordHashString::new(&value) {
                Ok(v) => {
                    validation_setter.set(Ok(()));
                    callback.emit(Some(v));
                }
                Err(e) => {
                    validation_setter.set(Err(e));
                    callback.emit(None);
                }
            }
        }
    };
    let onclick = {
        let setter = value.setter();
        let validation_setter = validation.setter();
        let callback = props.onchange.clone();
        move |_| {
            let value = LocalStorage::get::<String>("hash").unwrap_or_default();
            setter.set(value.clone());
            match PasswordHashString::new(&value) {
                Ok(v) => {
                    validation_setter.set(Ok(()));
                    callback.emit(Some(v));
                }
                Err(e) => {
                    validation_setter.set(Err(e));
                    callback.emit(None);
                }
            }
        }
    };
    let class = [
        Some("form-control"),
        match &*validation {
            Ok(_) => Some("is-valid"),
            Err(_) => Some("is-invalid"),
        },
    ]
    .into_iter()
    .collect::<yew::Classes>();
    yew::html! {
        <div class={yew::classes!("input-group", "has-validation")}>
        <label for="hash-expected" class={yew::classes!("input-group-prepend", "input-group-text")}>{"Hash (expected)"}</label>
        <input type="text" id="hash-expected" class={class} value={(*value).clone()} onchange={onchange} />
        <div class="input-group-append">
        <button type="button" class={yew::classes!("btn", "btn-outline-secondary")} onclick={onclick}>
        <i class="bi bi-file-earmark-arrow-down" />
        </button>
        </div>
        if let Err(e) = &*validation {
            <div class={yew::classes!("invalid-feedback")}>{e.to_string()}</div>
        }
        </div>
    }
}

#[derive(PartialEq, yew::Properties)]
struct AlgorithmInputProps {
    onchange: yew::Callback<Algorithm>,
}

#[yew::function_component]
fn AlgorithmInput(props: &AlgorithmInputProps) -> yew::Html {
    let value = yew::use_state(Algorithm::default);
    let onchange = {
        let setter = value.setter();
        let callback = props.onchange.clone();
        move |event: Event| {
            let value = event
                .target_dyn_into::<HtmlSelectElement>()
                .unwrap()
                .value()
                .parse()
                .unwrap();
            setter.set(value);
            callback.emit(value);
        }
    };
    let options = Algorithm::iter()
        .map(|v| {
            yew::html! {
                <option value={v.to_string()} selected={v == *value}>{v.get_message()}</option>
            }
        })
        .collect::<Vec<_>>();
    yew::html! {
        <div class="input-group">
        <label for="algorithm" class={yew::classes!("input-group-text")}>{"Algorithm"}</label>
        <select id="algorithm" class={yew::classes!("form-select")} onchange={onchange}>{options}</select>
        </div>
    }
}

#[derive(PartialEq, yew::Properties)]
struct SaltInputProps {
    onchange: yew::Callback<String>,
    validation: Option<Result<(), String>>,
}

#[yew::function_component]
fn SaltInput(props: &SaltInputProps) -> yew::Html {
    let value = yew::use_state(String::new);
    let onchange = {
        let setter = value.setter();
        let callback = props.onchange.clone();
        move |event: Event| {
            let value = event.target_dyn_into::<HtmlInputElement>().unwrap().value();
            setter.set(value.clone());
            callback.emit(value);
        }
    };
    let class_a = [
        Some("input-group"),
        props.validation.as_ref().map(|_| "has-validation"),
    ]
    .into_iter()
    .collect::<yew::Classes>();
    let class_b = [
        Some("form-control"),
        match &props.validation {
            Some(Ok(_)) => Some("is-valid"),
            Some(Err(_)) => Some("is-invalid"),
            None => None,
        },
    ]
    .into_iter()
    .collect::<yew::Classes>();
    yew::html! {
        <div class={class_a}>
        <label for="salt" class={yew::classes!("input-group-prepend", "input-group-text")}>{"Salt"}</label>
        <input type="salt" id="text" class={class_b} value={(*value).clone()} onchange={onchange} />
        if let Some(Err(e)) = &props.validation {
            <div class={yew::classes!("invalid-feedback")}>{e.to_string()}</div>
        }
        </div>
    }
}

#[derive(PartialEq, yew::Properties)]
struct KeyOutputProps {
    value: Option<String>,
}

#[yew::function_component]
fn KeyOutput(props: &KeyOutputProps) -> yew::Html {
    let visible = yew::use_state(|| false);
    let onclick_visible = {
        let visible = visible.clone();
        move |_| visible.set(!*visible)
    };
    let clipboard =
        yew::use_state(|| web_sys::window().and_then(|window| window.navigator().clipboard()));
    let clipboard_state = yew::use_state(|| false);
    let onclick_clipboard = {
        let clipboard = clipboard.clone();
        let clipboard_state = clipboard_state.setter();
        let value = props.value.clone();
        move |_| {
            let clipboard = clipboard.clone();
            let clipboard_state = clipboard_state.clone();
            let value = value.clone();
            wasm_bindgen_futures::spawn_local(
                async move {
                    let clipboard = clipboard.as_ref()?;
                    JsFuture::from(clipboard.write_text(value.as_deref().unwrap_or_default()))
                        .await
                        .ok()?;
                    clipboard_state.set(true);
                    gloo::timers::future::sleep(Duration::from_secs(1)).await;
                    clipboard_state.set(false);
                    Some(())
                }
                .map(|_| ()),
            );
        }
    };
    yew::html! {
        <div class="input-group">
        <label for="key" class={yew::classes!("input-group-prepend", "input-group-text")}>{"Key"}</label>
        <input
        id="key"
        type={if *visible { "text" } else { "password" }}
        class={yew::classes!("form-control")}
        value={props.value.clone().unwrap_or_default()}
        readonly=true disabled={props.value.is_none()} />
        <div class="input-group-append">
        <button type="button" class={yew::classes!("btn", "btn-outline-secondary")} onclick={onclick_visible} disabled={props.value.is_none()}>
        if *visible {
            <i class="bi bi-eye" />
        } else {
            <i class="bi bi-eye-slash" />
        }
        </button>
        if clipboard.is_some() {
            <button type="button" class={yew::classes!("btn", "btn-outline-secondary")} onclick={onclick_clipboard} disabled={props.value.is_none()}>
            if *clipboard_state {
                <i class="bi bi-clipboard-check" />
            } else {
                <i class="bi bi-clipboard" />
            }
            </button>
        }
        </div>
        </div>
    }
}

fn s2k<D>(salt: &[u8], passphrase: &[u8], count: usize) -> digest::Output<D>
where
    D: digest::Digest,
{
    let mut hasher = D::new();
    for &b in salt.iter().chain(passphrase).cycle().take(count) {
        hasher.update([b]);
    }
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use sha2::Sha256;

    #[test]
    fn test_s2k() {
        // gpg --cipher-algo AES256 --s2k-count 65536 --s2k-digest SHA256 --s2k-mode 3 --symmetric <FILE>
        // gpg --list-packets --show-session-key <FILE>.gpg
        assert_eq!(
            super::s2k::<Sha256>(&hex!("3109800B39D9C9D6"), b"passphrase", 65536).as_slice(),
            hex!("4892EE6C021A36201DE80C625C7F2B654C3AAC4578308F03A22B67BF25E893F6"),
        );
    }
}
