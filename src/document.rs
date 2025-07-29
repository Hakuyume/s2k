use std::any;
use std::fmt;
use std::ops;
use wasm_bindgen::prelude::{JsCast, JsValue};
use web_sys::Element;
use web_sys::{Document, HtmlElement, HtmlInputElement};

pub(crate) fn get_element_by_id<T>(document: &Document, element_id: &str) -> Result<T, JsValue>
where
    T: JsCast,
{
    document
        .get_element_by_id(element_id)
        .ok_or_else(|| JsValue::from(&format!("missing `{element_id}`")))?
        .dyn_into()
        .map_err(|element| {
            JsValue::from(&format!(
                "`{}` is not type of `{}`",
                any::type_name::<T>(),
                element.tag_name(),
            ))
        })
}

pub(crate) fn set_icon(element: &Element, value: &str) -> Result<(), JsValue> {
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

pub(crate) struct InputGroup {
    group: HtmlElement,
    input: HtmlInputElement,
    validation: HtmlElement,
}

impl ops::Deref for InputGroup {
    type Target = HtmlInputElement;

    fn deref(&self) -> &Self::Target {
        &self.input
    }
}

impl InputGroup {
    pub(crate) fn new(document: &Document, element_id: &str) -> Result<Self, JsValue> {
        Ok(Self {
            group: get_element_by_id(document, &format!("{element_id}:group"))?,
            input: get_element_by_id(document, element_id)?,
            validation: get_element_by_id(document, &format!("{element_id}:validation"))?,
        })
    }

    pub(crate) fn set_validation<T, E>(&self, value: Option<Result<T, E>>) -> Result<(), JsValue>
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
