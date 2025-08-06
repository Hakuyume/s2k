use futures::TryFutureExt;
use futures::channel::oneshot;
use std::any;
use std::fmt;
use std::ops;
use std::rc::Rc;
use std::time::Duration;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::Element;
use web_sys::HtmlElement;
use web_sys::HtmlInputElement;
use web_sys::{Clipboard, Document, Storage, Window};

pub(crate) type JsResult<T> = Result<T, JsValue>;

#[derive(Clone)]
pub(crate) struct Context {
    window: Rc<Window>,
    clipboard: Rc<Clipboard>,
    document: Rc<Document>,
    storage: Rc<Storage>,
}

impl Context {
    pub(crate) fn new() -> JsResult<Self> {
        let window = web_sys::window().ok_or_else(|| JsValue::from("missing window"))?;
        let clipboard = window.navigator().clipboard();
        let document = window
            .document()
            .ok_or_else(|| JsValue::from("missing document"))?;
        let storage = window
            .local_storage()?
            .ok_or_else(|| JsValue::from("missing local_storage"))?;
        Ok(Self {
            window: Rc::new(window),
            clipboard: Rc::new(clipboard),
            document: Rc::new(document),
            storage: Rc::new(storage),
        })
    }

    pub(crate) fn clipboard(&self) -> &Clipboard {
        &self.clipboard
    }

    pub(crate) fn storage(&self) -> &Storage {
        &self.storage
    }

    pub(crate) fn get_element_by_id<T>(&self, element_id: &str) -> JsResult<Rc<T>>
    where
        T: JsCast,
    {
        self.document
            .get_element_by_id(element_id)
            .ok_or_else(|| JsValue::from(&format!("missing `{element_id}`")))?
            .dyn_into()
            .map(Rc::new)
            .map_err(|element| {
                JsValue::from(&format!(
                    "`{}` is not type of `{}`",
                    any::type_name::<T>(),
                    element.tag_name(),
                ))
            })
    }

    pub(crate) fn sleep(&self, duration: Duration) -> impl Future<Output = JsResult<()>> + 'static {
        fn defer<F>(f: F) -> impl Drop
        where
            F: FnOnce(),
        {
            struct Guard<F>(Option<F>)
            where
                F: FnOnce();

            impl<F> Drop for Guard<F>
            where
                F: FnOnce(),
            {
                fn drop(&mut self) {
                    if let Some(f) = self.0.take() {
                        f()
                    }
                }
            }

            Guard(Some(f))
        }

        let (tx, rx) = oneshot::channel();
        let handle = self
            .window
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                wasm_bindgen::prelude::Closure::once(move || {
                    let _ = tx.send(());
                })
                .into_js_value()
                .unchecked_ref(),
                duration.as_millis() as _,
            );
        let window = self.window.clone();
        async move {
            let handle = handle?;
            let _guard = defer(|| window.clear_timeout_with_handle(handle));
            rx.map_err(|e| JsValue::from(&e.to_string())).await
        }
    }
}

pub(crate) fn set_icon(element: &Element, value: &str) -> JsResult<()> {
    let class_list = element.class_list();
    for item in class_list.value().split_whitespace() {
        if let Some(v) = item.strip_prefix("bi-")
            && v != value
        {
            class_list.remove_1(item)?;
        }
    }
    class_list.add_2("bi", &format!("bi-{value}"))?;
    Ok(())
}

#[derive(Clone)]
pub(crate) struct InputValidation {
    group: Rc<HtmlElement>,
    input: Rc<HtmlInputElement>,
    validation: Rc<HtmlElement>,
}

impl ops::Deref for InputValidation {
    type Target = HtmlInputElement;

    fn deref(&self) -> &Self::Target {
        &self.input
    }
}

impl InputValidation {
    pub(crate) fn new(cx: &Context, element_id: &str) -> JsResult<Self> {
        Ok(Self {
            group: cx.get_element_by_id(&format!("{element_id}:group"))?,
            input: cx.get_element_by_id(element_id)?,
            validation: cx.get_element_by_id(&format!("{element_id}:validation"))?,
        })
    }

    pub(crate) fn set_validation<T, E>(&self, value: Option<Result<T, E>>) -> JsResult<()>
    where
        E: fmt::Display,
    {
        let group = self.group.class_list();
        let input = self.input.class_list();
        match value {
            Some(Ok(_)) => {
                group.add_1("has-validation")?;
                input.remove_1("is-invalid")?;
                input.add_1("is-valid")?;
            }
            Some(Err(e)) => {
                group.add_1("has-validation")?;
                input.remove_1("is-valid")?;
                input.add_1("is-invalid")?;
                self.validation.set_inner_text(&e.to_string());
            }
            None => {
                group.remove_1("has-validation")?;
                input.remove_2("is-valid", "is-invalid")?;
            }
        }
        Ok(())
    }
}
