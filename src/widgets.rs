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
    (CONTROL($c:literal)) => {
        ::crossterm::event::Event::Key(::crossterm::event::KeyEvent {
            code: ::crossterm::event::KeyCode::Char($c),
            modifiers: ::crossterm::event::KeyModifiers::CONTROL,
            kind: ::crossterm::event::KeyEventKind::Press
                | ::crossterm::event::KeyEventKind::Repeat,
            ..
        })
    };
    (__CODE($code:pat)) => {
        ::crossterm::event::Event::Key(::crossterm::event::KeyEvent {
            code: $code,
            modifiers: ::crossterm::event::KeyModifiers::NONE,
            kind: ::crossterm::event::KeyEventKind::Press
                | ::crossterm::event::KeyEventKind::Repeat,
            ..
        })
    };
    (UP) => {
        $crate::key!(CONTROL('p')) | $crate::key!(__CODE(::crossterm::event::KeyCode::Up))
    };
    (DOWN) => {
        $crate::key!(CONTROL('n')) | $crate::key!(__CODE(::crossterm::event::KeyCode::Down))
    };
    (LEFT) => {
        $crate::key!(CONTROL('b')) | $crate::key!(__CODE(::crossterm::event::KeyCode::Left))
    };
    (RIGHT) => {
        $crate::key!(CONTROL('f')) | $crate::key!(__CODE(::crossterm::event::KeyCode::Right))
    };
    (ENTER) => {
        $crate::key!(CONTROL('m')) | $crate::key!(__CODE(::crossterm::event::KeyCode::Enter))
    };
    (BACKSPACE) => {
        $crate::key!(CONTROL('h')) | $crate::key!(__CODE(::crossterm::event::KeyCode::Backspace))
    };
}
