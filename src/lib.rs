mod algorithm;
mod document;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{self, PasswordHashString, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use futures::channel::oneshot;
use futures::{FutureExt, TryFutureExt};
use std::future;
use std::pin;
use std::time::Duration;
use strum::{EnumMessage, IntoEnumIterator};
use tokio::sync::watch;
use wasm_bindgen::prelude::{JsCast, JsValue, wasm_bindgen};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    Clipboard, Document, HtmlButtonElement, HtmlInputElement, HtmlOptionElement, HtmlSelectElement,
    Storage, Window,
};

const STORAGE_KEY: &str = concat!(env!("CARGO_CRATE_NAME"), "/hash");

#[wasm_bindgen(start)]
pub async fn start() -> Result<(), JsValue> {
    let argon2 = Argon2::default();
    let argon2 = &argon2;

    let window = web_sys::window().ok_or_else(|| JsValue::from("missing window"))?;
    let document = window
        .document()
        .ok_or_else(|| JsValue::from("missing document"))?;
    let storage = window
        .local_storage()?
        .ok_or_else(|| JsValue::from("missing local_storage"))?;
    let clipboard = window.navigator().clipboard();

    let (f0, password) = {
        let (password, password_validation, f0) = password(&document)?;
        let (hash_actual, f1) = hash_actual(&document, &storage)?;
        let (hash_expected, f2) = hash_expected(&document, &storage)?;
        let f = futures::future::try_join5(
            f0,
            f1,
            f2,
            watch1(password.clone(), {
                async move |password| {
                    let value = argon2
                        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
                        .map_err(|e| JsValue::from(&e.to_string()))?
                        .serialize();
                    let _ = hash_actual.send(Some(value));
                    Ok(())
                }
            }),
            watch2(
                password.clone(),
                hash_expected,
                async move |password, hash_expected| {
                    let _ = password_validation.send(hash_expected.as_ref().map(|hash_expected| {
                        argon2.verify_password(password.as_bytes(), &hash_expected.password_hash())
                    }));
                    Ok(())
                },
            ),
        );
        (f, password)
    };
    let f1 = {
        let algorithm = algorithm(&document)?;
        let (salt, salt_validation, f0) = salt(&document)?;
        let (key, f1) = key(&window, &document, &clipboard)?;
        futures::future::try_join3(
            f0,
            f1,
            watch3(
                password.clone(),
                algorithm,
                salt,
                async move |password, algorithm, salt| {
                    match algorithm.key(argon2, password, salt) {
                        Ok(v) => {
                            let _ = salt_validation.send(Some(Ok(())));
                            let _ = key.send(Some(v));
                        }
                        Err(e) => {
                            let _ = salt_validation.send(Some(Err(e)));
                            let _ = key.send(None);
                        }
                    }
                    Ok(())
                },
            ),
        )
    };

    futures::future::try_join(f0, f1).map_ok(|_| ()).await
}

fn password(
    document: &Document,
) -> Result<
    (
        watch::Receiver<String>,
        watch::Sender<Option<Result<(), password_hash::Error>>>,
        impl Future<Output = Result<impl Sized, JsValue>>,
    ),
    JsValue,
> {
    let (tx, rx) = watch::channel(String::new());
    let (validation_tx, validation_rx) = watch::channel(None);

    let input = document::InputGroup::new(&document, "password")?;
    let clear = document::get_element_by_id::<HtmlButtonElement>(&document, "password:clear")?;

    let f = futures::future::try_join(
        watch1(rx.clone(), {
            let input = input.clone();
            async move |value| {
                input.set_value(value);
                Ok(())
            }
        }),
        watch1(validation_rx.clone(), {
            let input = input.clone();
            async move |validation| input.set_validation(validation.as_ref().map(Result::as_ref))
        }),
    );

    input.set_onchange(Some(
        Closure::new({
            let tx = tx.clone();
            let input = input.clone();
            move || {
                let _ = tx.send(input.value());
                Ok(())
            }
        })
        .into_js_value()
        .unchecked_ref(),
    ));
    clear.set_onclick(Some(
        Closure::new({
            let tx = tx.clone();
            move || {
                let _ = tx.send(String::new());
                Ok(())
            }
        })
        .into_js_value()
        .unchecked_ref(),
    ));

    Ok((rx, validation_tx, f))
}

fn hash_actual(
    document: &Document,
    storage: &Storage,
) -> Result<
    (
        watch::Sender<Option<PasswordHashString>>,
        impl Future<Output = Result<impl Sized, JsValue>>,
    ),
    JsValue,
> {
    let (tx, rx) = watch::channel::<Option<PasswordHashString>>(None);

    let output = document::get_element_by_id::<HtmlInputElement>(&document, "hash-actual")?;
    let store = document::get_element_by_id::<HtmlButtonElement>(&document, "hash-actual:store")?;

    let f = watch1(rx.clone(), {
        let output = output.clone();
        async move |value| {
            if let Some(value) = value {
                output.set_value(value.as_str());
            }
            Ok(())
        }
    });

    store.set_onclick(Some(
        Closure::new({
            let rx = rx.clone();
            let storage = storage.clone();
            move || {
                if let Some(value) = &*rx.borrow() {
                    storage.set(STORAGE_KEY, value.as_str())?;
                }
                Ok(())
            }
        })
        .into_js_value()
        .unchecked_ref(),
    ));

    Ok((tx, f))
}

fn hash_expected(
    document: &Document,
    storage: &Storage,
) -> Result<
    (
        watch::Receiver<Option<PasswordHashString>>,
        impl Future<Output = Result<impl Sized, JsValue>>,
    ),
    JsValue,
> {
    let (tx, rx) = watch::channel(None);
    let (input_tx, input_rx) = watch::channel(String::new());

    let input = document::InputGroup::new(&document, "hash-expected")?;
    let load = document::get_element_by_id::<HtmlButtonElement>(&document, "hash-expected:load")?;

    let f = watch1(input_rx.clone(), {
        let input = input.clone();
        async move |value| {
            input.set_value(value);
            let value = PasswordHashString::new(value);
            input.set_validation(Some(value.as_ref()))?;
            let _ = tx.send(value.ok());
            Ok(())
        }
    });

    input.set_onchange(Some(
        Closure::new({
            let tx = input_tx.clone();
            let input = input.clone();
            move || {
                let _ = tx.send(input.value());
                Ok(())
            }
        })
        .into_js_value()
        .unchecked_ref(),
    ));
    load.set_onclick(Some(
        Closure::new({
            let tx = input_tx.clone();
            let storage = storage.clone();
            move || {
                if let Some(value) = storage.get(STORAGE_KEY)? {
                    let _ = tx.send(value);
                }
                Ok(())
            }
        })
        .into_js_value()
        .unchecked_ref(),
    ));

    Ok((rx, f))
}

fn algorithm(document: &Document) -> Result<watch::Receiver<algorithm::Algorithm>, JsValue> {
    let (tx, rx) = watch::channel(algorithm::Algorithm::default());

    let input = document::get_element_by_id::<HtmlSelectElement>(document, "algorithm")?;

    let options = input.options();
    options.set_length(0);
    for algorithm in algorithm::Algorithm::iter() {
        let option = HtmlOptionElement::new()?;
        option.set_value(&algorithm.to_string());
        if let Some(message) = algorithm.get_message() {
            option.set_inner_text(message);
        }
        if algorithm == algorithm::Algorithm::default() {
            option.set_selected(true);
        }
        options.add_with_html_option_element(&option)?;
    }

    input.set_onchange(Some(
        Closure::new({
            let input = input.clone();
            move || {
                let _ = tx.send(
                    input
                        .value()
                        .parse::<algorithm::Algorithm>()
                        .map_err(|e| JsValue::from(&e.to_string()))?,
                );
                Ok(())
            }
        })
        .into_js_value()
        .unchecked_ref(),
    ));

    Ok(rx)
}

fn salt(
    document: &Document,
) -> Result<
    (
        watch::Receiver<String>,
        watch::Sender<Option<Result<(), argon2::Error>>>,
        impl Future<Output = Result<impl Sized, JsValue>>,
    ),
    JsValue,
> {
    let (tx, rx) = watch::channel(String::new());
    let (validation_tx, validation_rx) = watch::channel(None);

    let input = document::InputGroup::new(document, "salt")?;

    let f = futures::future::try_join(
        watch1(rx.clone(), {
            let input = input.clone();
            async move |value| {
                input.set_value(value);
                Ok(())
            }
        }),
        watch1(validation_rx.clone(), {
            let input = input.clone();
            async move |validation| input.set_validation(validation.as_ref().map(Result::as_ref))
        }),
    );

    input.set_onchange(Some(
        Closure::new({
            let tx = tx.clone();
            let input = input.clone();
            move || {
                let _ = tx.send(input.value());
                Ok(())
            }
        })
        .into_js_value()
        .unchecked_ref(),
    ));

    Ok((rx, validation_tx, f))
}

fn key(
    window: &Window,
    document: &Document,
    clipboard: &Clipboard,
) -> Result<
    (
        watch::Sender<Option<String>>,
        impl Future<Output = Result<impl Sized, JsValue>>,
    ),
    JsValue,
> {
    let (tx, rx) = watch::channel::<Option<String>>(None);
    let (visible_tx, visible_rx) = watch::channel(false);
    let (copy_icon_tx, copy_icon_rx) = watch::channel(false);

    let output = document::get_element_by_id::<HtmlInputElement>(&document, "key")?;
    let toggle = document::get_element_by_id::<HtmlButtonElement>(&document, "key:toggle")?;
    let copy = document::get_element_by_id::<HtmlButtonElement>(&document, "key:copy")?;

    let f = futures::future::try_join3(
        watch1(rx.clone(), {
            let output = output.clone();
            let toggle = toggle.clone();
            let copy = copy.clone();
            async move |value| {
                output.set_value(value.as_deref().unwrap_or_default());
                output.set_disabled(value.is_none());
                toggle.set_disabled(value.is_none());
                copy.set_disabled(value.is_none());
                Ok(())
            }
        }),
        watch1(visible_rx.clone(), {
            let output = output.clone();
            let toggle = toggle.clone();
            async move |visible| {
                if *visible {
                    output.set_type("text");
                    document::set_icon(&toggle, "eye")?;
                } else {
                    output.set_type("password");
                    document::set_icon(&toggle, "eye-slash")?;
                }
                Ok(())
            }
        }),
        watch1(copy_icon_rx.clone(), {
            let copy = copy.clone();
            async move |copy_icon| {
                if *copy_icon {
                    document::set_icon(&copy, "clipboard-check")?;
                } else {
                    document::set_icon(&copy, "clipboard")?;
                }
                Ok(())
            }
        }),
    );

    toggle.set_onclick(Some(
        Closure::new({
            let tx = visible_tx.clone();
            move || {
                tx.send_modify(|v| *v = !*v);
                Ok(())
            }
        })
        .into_js_value()
        .unchecked_ref(),
    ));
    copy.set_onclick(Some(
        Closure::new({
            let rx = rx.clone();
            let copy_icon_tx = copy_icon_tx.clone();
            let window = window.clone();
            let clipboard = clipboard.clone();
            move || {
                let rx = rx.clone();
                let copy_icon_tx = copy_icon_tx.clone();
                let window = window.clone();
                let clipboard = clipboard.clone();
                wasm_bindgen_futures::spawn_local(
                    async move {
                        if let Some(value) = &*rx.borrow() {
                            JsFuture::from(clipboard.write_text(value)).await?;
                            let _ = copy_icon_tx.send(true);
                            sleep(&window, Duration::from_secs(1)).await?;
                            let _ = copy_icon_tx.send(false);
                        }
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

    Ok((tx, f))
}

type Closure = wasm_bindgen::prelude::Closure<dyn FnMut() -> Result<(), JsValue>>;

async fn watch1<T0, F>(mut rx0: watch::Receiver<T0>, mut f: F) -> Result<(), JsValue>
where
    F: AsyncFnMut(&T0) -> Result<(), JsValue>,
{
    loop {
        f(&*rx0.borrow_and_update()).await?;
        if rx0.changed().await.is_err() {
            break Ok(());
        }
    }
}

async fn watch2<T0, T1, F>(
    mut rx0: watch::Receiver<T0>,
    mut rx1: watch::Receiver<T1>,
    mut f: F,
) -> Result<(), JsValue>
where
    F: AsyncFnMut(&T0, &T1) -> Result<(), JsValue>,
{
    loop {
        f(&*rx0.borrow_and_update(), &*rx1.borrow_and_update()).await?;
        if futures::future::try_select(pin::pin!(rx0.changed()), pin::pin!(rx1.changed()))
            .await
            .is_err()
        {
            break Ok(());
        }
    }
}

async fn watch3<T0, T1, T2, F>(
    mut rx0: watch::Receiver<T0>,
    mut rx1: watch::Receiver<T1>,
    mut rx2: watch::Receiver<T2>,
    mut f: F,
) -> Result<(), JsValue>
where
    F: AsyncFnMut(&T0, &T1, &T2) -> Result<(), JsValue>,
{
    loop {
        f(
            &*rx0.borrow_and_update(),
            &*rx1.borrow_and_update(),
            &*rx2.borrow_and_update(),
        )
        .await?;
        if futures::future::try_select(
            futures::future::try_select(pin::pin!(rx0.changed()), pin::pin!(rx1.changed())),
            pin::pin!(rx2.changed()),
        )
        .await
        .is_err()
        {
            break Ok(());
        }
    }
}

fn sleep(
    window: &Window,
    duration: Duration,
) -> impl Future<Output = Result<(), JsValue>> + 'static {
    let (tx, rx) = oneshot::channel();
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
