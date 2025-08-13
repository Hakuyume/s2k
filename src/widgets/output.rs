use ratatui::style::{self, Stylize};
use ratatui::{layout, widgets};
use std::borrow::Cow;
use std::iter;

pub struct Output<'a> {
    state: &'a mut OutputState,
    title: &'a str,
    actions: Vec<(&'a str, bool)>,
}

impl<'a> Output<'a> {
    pub fn new(state: &'a mut OutputState, title: &'a str) -> Self {
        Self {
            state,
            title,
            actions: Vec::new(),
        }
    }

    pub fn actions<I>(mut self, value: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, bool)>,
    {
        self.actions = value.into_iter().collect();
        self
    }

    pub fn vertical(&self) -> layout::Constraint {
        layout::Constraint::Length(1 + 2)
    }

    pub fn render(self, frame: &mut ratatui::Frame, area: layout::Rect) {
        let value = self.state.value.as_deref().unwrap_or_default();
        let value = if self.state.masked {
            Cow::Owned(iter::repeat_n(super::MASK, value.chars().count()).collect())
        } else {
            Cow::Borrowed(value)
        };
        let block = super::block(self.title, self.actions).style(if self.state.value.is_some() {
            style::Style::default()
        } else {
            style::Style::default().gray()
        });
        frame.render_widget(widgets::Paragraph::new(value).block(block), area);
    }
}

#[derive(Default)]
pub struct OutputState {
    value: Option<String>,
    masked: bool,
}

impl OutputState {
    pub fn with_masked(mut self, value: bool) -> Self {
        self.masked = value;
        self
    }

    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    pub fn set_value<T>(&mut self, value: Option<T>)
    where
        T: Into<String>,
    {
        self.value = value.map(Into::into);
    }

    pub fn masked(&self) -> bool {
        self.masked
    }

    pub fn set_masked(&mut self, value: bool) {
        self.masked = value;
    }
}
