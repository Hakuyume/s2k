mod algorithm;
mod web;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{self, PasswordHashString, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use futures::TryFutureExt;
use std::pin;
use std::rc::Rc;
use std::time::Duration;
use strum::{EnumMessage, IntoEnumIterator};
use tokio::sync::watch;
use wasm_bindgen::prelude::{JsCast, JsValue, wasm_bindgen};
use wasm_bindgen_futures::JsFuture;
use web::JsResult;
use web_sys::{HtmlButtonElement, HtmlInputElement, HtmlOptionElement, HtmlSelectElement};

const STORAGE_KEY: &str = concat!(env!("CARGO_CRATE_NAME"), "/hash");

#[wasm_bindgen(start)]
pub async fn start() -> JsResult<()> {
    let argon2 = Argon2::default();
    let argon2 = &argon2;

    let cx = web::Context::new()?;

    let (f0, password) = {
        let (password, password_validation, f0) = password(&cx)?;
        let (hash_actual, f1) = hash_actual(&cx)?;
        let (hash_expected, f2) = hash_expected(&cx)?;
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
        let algorithm = algorithm(&cx)?;
        let (salt, salt_validation, f0) = salt(&cx)?;
        let (key, f1) = key(&cx)?;
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

type Closure = wasm_bindgen::prelude::Closure<dyn FnMut() -> JsResult<()>>;
type Validation<E> = watch::Sender<Option<Result<(), E>>>;

fn password(
    cx: &web::Context,
) -> JsResult<(
    watch::Receiver<String>,
    Validation<password_hash::Error>,
    impl Future<Output = JsResult<impl Sized>>,
)> {
    let (tx, rx) = watch::channel(String::new());
    let (validation_tx, validation_rx) = watch::channel(None);

    let input = web::InputValidation::new(cx, "password")?;
    let clear = cx.get_element_by_id::<HtmlButtonElement>("password:clear")?;

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
    cx: &web::Context,
) -> JsResult<(
    watch::Sender<Option<PasswordHashString>>,
    impl Future<Output = JsResult<impl Sized>>,
)> {
    let (tx, rx) = watch::channel::<Option<PasswordHashString>>(None);

    let output = cx.get_element_by_id::<HtmlInputElement>("hash-actual")?;
    let store = cx.get_element_by_id::<HtmlButtonElement>("hash-actual:store")?;

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
            let cx = cx.clone();
            move || {
                if let Some(value) = &*rx.borrow() {
                    cx.storage().set(STORAGE_KEY, value.as_str())?;
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
    cx: &web::Context,
) -> JsResult<(
    watch::Receiver<Option<PasswordHashString>>,
    impl Future<Output = JsResult<impl Sized>>,
)> {
    let (tx, rx) = watch::channel(None);
    let (input_tx, input_rx) = watch::channel(String::new());

    let input = web::InputValidation::new(cx, "hash-expected")?;
    let load = cx.get_element_by_id::<HtmlButtonElement>("hash-expected:load")?;

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
            let cx = cx.clone();
            move || {
                if let Some(value) = cx.storage().get(STORAGE_KEY)? {
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

fn algorithm(cx: &web::Context) -> JsResult<watch::Receiver<algorithm::Algorithm>> {
    let (tx, rx) = watch::channel(algorithm::Algorithm::default());

    let input = cx.get_element_by_id::<HtmlSelectElement>("algorithm")?;

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
    cx: &web::Context,
) -> JsResult<(
    watch::Receiver<String>,
    Validation<argon2::Error>,
    impl Future<Output = JsResult<impl Sized>>,
)> {
    let (tx, rx) = watch::channel(String::new());
    let (validation_tx, validation_rx) = watch::channel(None);

    let input = web::InputValidation::new(cx, "salt")?;

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
    cx: &web::Context,
) -> JsResult<(
    watch::Sender<Option<String>>,
    impl Future<Output = JsResult<impl Sized>>,
)> {
    let (tx, rx) = watch::channel::<Option<String>>(None);
    let (visible_tx, visible_rx) = watch::channel(false);
    let copy_notify = Rc::new(tokio::sync::Notify::new());
    let (copy_state_tx, copy_state_rx) = watch::channel(false);

    let output = cx.get_element_by_id::<HtmlInputElement>("key")?;
    let toggle = cx.get_element_by_id::<HtmlButtonElement>("key:toggle")?;
    let copy = cx.get_element_by_id::<HtmlButtonElement>("key:copy")?;

    let f = futures::future::try_join4(
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
                    web::set_icon(&toggle, "eye")?;
                } else {
                    output.set_type("password");
                    web::set_icon(&toggle, "eye-slash")?;
                }
                Ok(())
            }
        }),
        {
            let rx = rx.clone();
            let copy_notify = copy_notify.clone();
            let copy_state_tx = copy_state_tx.clone();
            let cx = cx.clone();
            async move {
                loop {
                    copy_notify.notified().await;
                    if let Some(value) = &*rx.borrow() {
                        JsFuture::from(cx.clipboard().write_text(value)).await?;
                        let _ = copy_state_tx.send(true);
                        cx.sleep(Duration::from_secs(1)).await?;
                    }
                    let _ = copy_state_tx.send(false);
                }
                #[allow(unreachable_code)]
                Ok(())
            }
        },
        watch1(copy_state_rx.clone(), {
            let copy = copy.clone();
            async move |copy_state| {
                if *copy_state {
                    web::set_icon(&copy, "clipboard-check")?;
                } else {
                    web::set_icon(&copy, "clipboard")?;
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
            let notify = copy_notify.clone();
            move || {
                notify.notify_waiters();
                Ok(())
            }
        })
        .into_js_value()
        .unchecked_ref(),
    ));

    Ok((tx, f))
}

async fn watch1<T0, F>(mut rx0: watch::Receiver<T0>, mut f: F) -> JsResult<()>
where
    F: AsyncFnMut(&T0) -> JsResult<()>,
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
) -> JsResult<()>
where
    F: AsyncFnMut(&T0, &T1) -> JsResult<()>,
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
) -> JsResult<()>
where
    F: AsyncFnMut(&T0, &T1, &T2) -> JsResult<()>,
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
