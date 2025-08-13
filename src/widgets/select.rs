use ratatui::crossterm::event;
use ratatui::layout;
use ratatui::style::{self, Stylize};
use ratatui::widgets;
use std::marker::PhantomData;
use std::ops::ControlFlow;

pub struct Select<'a, T> {
    state: &'a mut SelectState<T>,
    title: &'a str,
    editing: bool,
    actions: Vec<(&'a str, bool)>,
}

impl<'a, T> Select<'a, T> {
    pub fn new(state: &'a mut SelectState<T>, title: &'a str) -> Self {
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

    pub fn vertical(&self) -> layout::Constraint
    where
        T: strum::EnumCount,
    {
        if self.editing {
            layout::Constraint::Length(T::COUNT as u16 + 2)
        } else {
            layout::Constraint::Length(1 + 2)
        }
    }

    pub fn render(self, frame: &mut ratatui::Frame, area: layout::Rect)
    where
        T: strum::EnumMessage + strum::VariantArray,
    {
        let block = super::block(self.title, self.actions);
        if self.editing {
            frame.render_stateful_widget(
                widgets::List::new(T::VARIANTS.iter().map(|v| v.get_documentation().unwrap()))
                    .block(block)
                    .highlight_style(style::Style::default().reversed()),
                area,
                &mut self.state.state,
            );
        } else {
            frame.render_widget(
                widgets::Paragraph::new(self.state.value().get_documentation().unwrap())
                    .block(block),
                area,
            )
        }
    }
}

pub struct SelectState<T> {
    state: widgets::ListState,
    _marker: PhantomData<fn() -> T>,
}

impl<T> Default for SelectState<T> {
    fn default() -> Self {
        let state = widgets::ListState::default().with_selected(Some(0));
        Self {
            state,
            _marker: PhantomData,
        }
    }
}

impl<T> SelectState<T>
where
    T: strum::VariantArray,
{
    pub fn value(&self) -> &T {
        T::VARIANTS
            .get(self.state.selected().unwrap())
            .or(T::VARIANTS.last())
            .unwrap()
    }

    pub fn handle(&mut self, event: event::Event) -> ControlFlow<()> {
        match event {
            crate::key!(ENTER) => ControlFlow::Break(()),
            crate::key!(UP) => {
                self.state.select_previous();
                ControlFlow::Continue(())
            }
            crate::key!(DOWN) => {
                self.state.select_next();
                ControlFlow::Continue(())
            }
            _ => ControlFlow::Continue(()),
        }
    }
}
