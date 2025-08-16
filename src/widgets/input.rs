use ratatui::crossterm::event;
use ratatui::style::{self, Stylize};
use ratatui::{layout, text, widgets};
use std::borrow::Cow;
use std::fmt;
use std::iter;
use std::ops::ControlFlow;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub struct Input<'a> {
    state: &'a mut InputState,
    title: &'a str,
    editing: bool,
    actions: Vec<(&'a str, bool)>,
}

impl<'a> Input<'a> {
    pub fn new(state: &'a mut InputState, title: &'a str) -> Self {
        Self {
            state,
            title,
            editing: false,
            actions: Vec::new(),
        }
    }

    pub fn editing(mut self, value: bool) -> Self {
        self.editing = value;
        self
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
        let value = if self.state.masked {
            Cow::Owned(iter::repeat_n(super::MASK, self.state.value.chars().count()).collect())
        } else {
            Cow::Borrowed(self.state.value.as_str())
        };

        let (view, cursor) = if self.editing {
            let index = self.state.value[..self.state.index]
                .chars()
                .map(|c| if self.state.masked { super::MASK } else { c }.len_utf8())
                .sum::<usize>();
            let (view, cursor) = (0..=index)
                .filter(|i| value.is_char_boundary(*i))
                .flat_map(|i| {
                    let value = &value;
                    (index..=value.len()).filter_map(move |j| {
                        value
                            .is_char_boundary(j)
                            .then_some((&value[i..j], value[i..index].width_cjk()))
                    })
                })
                .filter(|(view, cursor)| {
                    view.width_cjk() + 2 <= area.width as _ && *cursor + 2 < area.width as _
                })
                .min_by_key(|(view, cursor)| {
                    (
                        usize::MAX - view.chars().count(),
                        self.state.cursor.abs_diff(*cursor),
                    )
                })
                .unwrap();
            self.state.cursor = cursor;
            (view, Some(cursor))
        } else {
            let view = (0..=value.len())
                .rev()
                .filter_map(|j| value.is_char_boundary(j).then_some(&value[..j]))
                .find(|view| view.width_cjk() + 2 <= area.width as _)
                .unwrap();
            (view, None)
        };

        let block = super::block(self.title, self.actions).style(
            match (self.editing, &self.state.validation) {
                (false, Some(Ok(_))) => style::Style::default().green(),
                (false, Some(Err(_))) => style::Style::default().red(),
                _ => style::Style::default(),
            },
        );
        let block = if !self.editing
            && let Some(Err(e)) = &self.state.validation
        {
            block.title_bottom(text::Line::raw(format!("\"{e}\"")).centered())
        } else {
            block
        };
        frame.render_widget(widgets::Paragraph::new(view).block(block), area);

        if let Some(cursor) = cursor {
            frame.set_cursor_position(layout::Position::new(
                area.x + 1 + cursor as u16,
                area.y + 1,
            ));
        }
    }
}

#[derive(Default)]
pub struct InputState {
    value: String,
    index: usize,
    cursor: usize,
    masked: bool,
    validation: Option<Result<(), String>>,
}

impl InputState {
    pub fn with_masked(mut self, value: bool) -> Self {
        self.masked = value;
        self
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn set_value<T>(&mut self, value: T)
    where
        T: Into<String>,
    {
        self.value = value.into();
        self.index = self.value.len();
    }

    pub fn set_validation<T, E>(&mut self, value: Option<Result<T, E>>)
    where
        E: fmt::Display,
    {
        self.validation = value.map(|value| value.map(|_| ()).map_err(|e| e.to_string()));
    }

    pub fn handle(&mut self, event: event::Event) -> ControlFlow<()> {
        match event {
            crate::key!(ENTER) => ControlFlow::Break(()),
            crate::key!(LEFT) => {
                if let Some((i, c)) = self
                    .value
                    .get(..self.index)
                    .and_then(|s| s.char_indices().next_back())
                {
                    self.index = i;
                    if let Some(width) = if self.masked { super::MASK } else { c }.width_cjk() {
                        self.cursor = self.cursor.saturating_sub(width);
                    }
                }
                ControlFlow::Continue(())
            }
            crate::key!(RIGHT) => {
                if let Some(c) = self.value.get(self.index..).and_then(|s| s.chars().next()) {
                    self.index += c.len_utf8();
                    if let Some(width) = if self.masked { super::MASK } else { c }.width_cjk() {
                        self.cursor += width;
                    }
                }
                ControlFlow::Continue(())
            }
            event::Event::Key(event::KeyEvent {
                code: event::KeyCode::Char(c),
                modifiers: event::KeyModifiers::NONE | event::KeyModifiers::SHIFT,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            }) => {
                self.value.insert(self.index, c);
                self.index += c.len_utf8();
                if let Some(width) = if self.masked { super::MASK } else { c }.width_cjk() {
                    self.cursor += width;
                }
                ControlFlow::Continue(())
            }
            crate::key!(BACKSPACE) => {
                if let Some((i, c)) = self
                    .value
                    .get(..self.index)
                    .and_then(|s| s.char_indices().next_back())
                {
                    self.value.remove(i);
                    self.index = i;
                    if let Some(width) = if self.masked { super::MASK } else { c }.width_cjk() {
                        self.cursor = self.cursor.saturating_sub(width);
                    }
                }
                ControlFlow::Continue(())
            }
            _ => ControlFlow::Continue(()),
        }
    }
}
