mod algorithm;
mod document;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use futures::{FutureExt, TryFutureExt};
use std::cell::RefCell;
use std::future;
use std::rc::Rc;
use std::time::Duration;
use strum::{EnumMessage, IntoEnumIterator};
use wasm_bindgen::prelude::{JsCast, JsValue, wasm_bindgen};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    Clipboard, HtmlButtonElement, HtmlInputElement, HtmlOptionElement, HtmlSelectElement, Storage,
    Window,
};

const STORAGE_KEY: &str = concat!(env!("CARGO_CRATE_NAME"), "/hash");

#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    let context = Context::new()?;
    context.init()?;
    Ok(())
}

struct Context {
    argon2: Argon2<'static>,
    hash_salt: RefCell<Option<SaltString>>,

    window: Window,
    local_storage: Storage,
    clipboard: Clipboard,

    password: document::InputGroup,
    password_clear: HtmlButtonElement,
    hash_actual: HtmlInputElement,
    hash_actual_store: HtmlButtonElement,
    hash_expected: document::InputGroup,
    hash_expected_load: HtmlButtonElement,
    algorithm: HtmlSelectElement,
    salt: document::InputGroup,
    key: HtmlInputElement,
    key_toggle: HtmlButtonElement,
    key_copy: HtmlButtonElement,
}

impl Context {
    fn new() -> Result<Rc<Self>, JsValue> {
        let window = web_sys::window().ok_or_else(|| JsValue::from("missing window"))?;
        let document = window
            .document()
            .ok_or_else(|| JsValue::from("missing document"))?;
        let local_storage = window
            .local_storage()?
            .ok_or_else(|| JsValue::from("missing local_storage"))?;
        let clipboard = window.navigator().clipboard();

        Ok(Rc::new(Self {
            argon2: Argon2::default(),
            hash_salt: RefCell::new(None),

            window,
            local_storage,
            clipboard,

            password: document::InputGroup::new(&document, "password")?,
            password_clear: document::get_element_by_id(&document, "password:clear")?,
            hash_actual: document::get_element_by_id(&document, "hash-actual")?,
            hash_actual_store: document::get_element_by_id(&document, "hash-actual:store")?,
            hash_expected: document::InputGroup::new(&document, "hash-expected")?,
            hash_expected_load: document::get_element_by_id(&document, "hash-expected:load")?,
            algorithm: document::get_element_by_id(&document, "algorithm")?,
            salt: document::InputGroup::new(&document, "salt")?,
            key: document::get_element_by_id(&document, "key")?,
            key_toggle: document::get_element_by_id(&document, "key:toggle")?,
            key_copy: document::get_element_by_id(&document, "key:copy")?,
        }))
    }

    fn init(self: Rc<Self>) -> Result<(), JsValue> {
        let options = self.algorithm.options();
        options.set_length(0);
        for algorithm in algorithm::Algorithm::iter() {
            let option = HtmlOptionElement::new()?;
            option.set_value(&algorithm.to_string());
            if let Some(message) = algorithm.get_message() {
                option.set_inner_text(message);
            }
            options.add_with_html_option_element(&option)?;
        }

        self.update()?;
        document::set_icon(&self.key_copy, "clipboard")?;

        type Closure = wasm_bindgen::prelude::Closure<dyn FnMut() -> Result<(), JsValue>>;
        self.password.set_onchange(Some(
            Closure::new({
                let this = self.clone();
                move || {
                    *this.hash_salt.borrow_mut() = None;
                    this.update()
                }
            })
            .into_js_value()
            .unchecked_ref(),
        ));
        self.password_clear.set_onclick(Some(
            Closure::new({
                let this = self.clone();
                move || {
                    this.password.set_value("");
                    this.update()
                }
            })
            .into_js_value()
            .unchecked_ref(),
        ));
        self.hash_actual_store.set_onclick(Some(
            Closure::new({
                let this = self.clone();
                move || {
                    this.local_storage
                        .set(STORAGE_KEY, &this.hash_actual.value())
                }
            })
            .into_js_value()
            .unchecked_ref(),
        ));
        self.hash_expected.set_onchange(Some(
            Closure::new({
                let this = self.clone();
                move || this.update()
            })
            .into_js_value()
            .unchecked_ref(),
        ));
        self.hash_expected_load.set_onclick(Some(
            Closure::new({
                let this = self.clone();
                move || {
                    if let Some(value) = this.local_storage.get(STORAGE_KEY)? {
                        this.hash_expected.set_value(&value);
                        this.update()?;
                    }
                    Ok(())
                }
            })
            .into_js_value()
            .unchecked_ref(),
        ));
        self.algorithm.set_onchange(Some(
            Closure::new({
                let this = self.clone();
                move || this.update()
            })
            .into_js_value()
            .unchecked_ref(),
        ));
        self.salt.set_onchange(Some(
            Closure::new({
                let this = self.clone();
                move || this.update()
            })
            .into_js_value()
            .unchecked_ref(),
        ));
        self.key_toggle.set_onclick(Some(
            Closure::new({
                let this = self.clone();
                move || {
                    match this.key.type_().as_str() {
                        "password" => this.key.set_type("text"),
                        "text" => this.key.set_type("password"),
                        _ => (),
                    }
                    this.update()
                }
            })
            .into_js_value()
            .unchecked_ref(),
        ));
        self.key_copy.set_onclick(Some(
            Closure::new({
                let this = self.clone();
                move || {
                    let this = this.clone();
                    wasm_bindgen_futures::spawn_local(
                        async move {
                            JsFuture::from(this.clipboard.write_text(&this.key.value())).await?;
                            document::set_icon(&this.key_copy, "clipboard-check")?;
                            sleep(&this.window, Duration::from_secs(1)).await?;
                            document::set_icon(&this.key_copy, "clipboard")?;
                            Ok::<_, JsValue>(())
                        }
                        .map(|_| ()),
                    );
                    Ok(())
                }
            })
            .into_js_value()
            .unchecked_ref(),
        ));

        Ok(())
    }

    fn update(&self) -> Result<(), JsValue> {
        let password = self.password.value();

        {
            let mut hash_salt = self.hash_salt.borrow_mut();
            let hash_salt = hash_salt.get_or_insert_with(|| SaltString::generate(&mut OsRng));
            let hash_actual = self
                .argon2
                .hash_password(password.as_bytes(), &*hash_salt)
                .map_err(|e| JsValue::from(&e.to_string()))?;
            let hash_expected = self.hash_expected.value();
            let hash_expected = PasswordHash::new(&hash_expected);
            let password_validation = hash_expected.as_ref().ok().map(|hash_expected| {
                self.argon2
                    .verify_password(password.as_bytes(), hash_expected)
            });

            self.password.set_validation(password_validation)?;
            self.hash_actual.set_value(&hash_actual.to_string());
            self.hash_expected
                .set_validation(Some(hash_expected.as_ref()))?;
        }

        {
            let algorithm = self
                .algorithm
                .value()
                .parse::<algorithm::Algorithm>()
                .map_err(|e| JsValue::from(&e.to_string()))?;
            let salt = self.salt.value();
            let key = algorithm.key(&self.argon2, password, salt);

            self.salt.set_validation(Some(key.as_ref()))?;
            self.key.set_value(key.as_deref().unwrap_or_default());
            self.key.set_disabled(key.is_err());
            self.key_toggle.set_disabled(key.is_err());
            self.key_copy.set_disabled(key.is_err());
        }

        {
            match self.key.type_().as_str() {
                "password" => {
                    document::set_icon(&self.key_toggle, "eye-slash")?;
                }
                "text" => {
                    document::set_icon(&self.key_toggle, "eye")?;
                }
                _ => (),
            }
        }
        Ok(())
    }
}

fn sleep(
    window: &Window,
    duration: Duration,
) -> impl Future<Output = Result<(), JsValue>> + 'static {
    let (tx, rx) = futures::channel::oneshot::channel();
    window
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            wasm_bindgen::prelude::Closure::once(move || {
                let _ = tx.send(());
            })
            .into_js_value()
            .unchecked_ref(),
            duration.as_millis() as _,
        )
        .map_or_else(
            |e| futures::future::Either::Right(future::ready(Err(e))),
            |_| futures::future::Either::Left(rx.map_err(|e| JsValue::from(&e.to_string()))),
        )
}
