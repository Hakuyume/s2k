mod input;
mod output;
mod select;

pub use input::{Input, InputState};
pub use output::{Output, OutputState};
use ratatui::style::{self, Stylize};
use ratatui::{text, widgets};
pub use select::{Select, SelectState};

const MASK: char = '*';

fn block<'a, I>(title: &'a str, actions: I) -> widgets::Block<'a>
where
    I: IntoIterator<Item = (&'a str, bool)>,
{
    actions.into_iter().fold(
        widgets::Block::bordered().title_top(text::Line::raw(title).left_aligned()),
        |block, (name, selected)| {
            block.title_bottom(
                text::Line::default()
                    .spans([
                        text::Span::raw("["),
                        text::Span::styled(
                            name,
                            if selected {
                                style::Style::default().reversed()
                            } else {
                                style::Style::default()
                            },
                        ),
                        text::Span::raw("]"),
                    ])
                    .right_aligned(),
            )
        },
    )
}

#[macro_export]
macro_rules! key {
    (UP) => {
        event::Event::Key(
            event::KeyEvent {
                code: event::KeyCode::Char('p'),
                modifiers: event::KeyModifiers::CONTROL,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            } | event::KeyEvent {
                code: event::KeyCode::Up,
                modifiers: event::KeyModifiers::NONE,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            },
        )
    };
    (DOWN) => {
        event::Event::Key(
            event::KeyEvent {
                code: event::KeyCode::Char('n'),
                modifiers: event::KeyModifiers::CONTROL,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            } | event::KeyEvent {
                code: event::KeyCode::Down,
                modifiers: event::KeyModifiers::NONE,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            },
        )
    };
    (LEFT) => {
        event::Event::Key(
            event::KeyEvent {
                code: event::KeyCode::Char('b'),
                modifiers: event::KeyModifiers::CONTROL,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            } | event::KeyEvent {
                code: event::KeyCode::Left,
                modifiers: event::KeyModifiers::NONE,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            },
        )
    };
    (RIGHT) => {
        event::Event::Key(
            event::KeyEvent {
                code: event::KeyCode::Char('f'),
                modifiers: event::KeyModifiers::CONTROL,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            } | event::KeyEvent {
                code: event::KeyCode::Right,
                modifiers: event::KeyModifiers::NONE,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            },
        )
    };
    (ENTER) => {
        event::Event::Key(
            event::KeyEvent {
                code: event::KeyCode::Char('m'),
                modifiers: event::KeyModifiers::CONTROL,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            } | event::KeyEvent {
                code: event::KeyCode::Enter,
                modifiers: event::KeyModifiers::NONE,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            },
        )
    };
    (BACKSPACE) => {
        event::Event::Key(
            event::KeyEvent {
                code: event::KeyCode::Char('h'),
                modifiers: event::KeyModifiers::CONTROL,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            } | event::KeyEvent {
                code: event::KeyCode::Backspace,
                modifiers: event::KeyModifiers::NONE,
                kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                ..
            },
        )
    };
}
