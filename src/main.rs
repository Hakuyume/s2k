mod s2k;
mod widgets;

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use bitflags::Flags;
use clap::Parser;
use crossterm::event;
use futures::{FutureExt, StreamExt};
use ratatui::layout;
use std::future;
use std::io;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::pin;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use widgets::{Input, InputState, Output, OutputState, Select, SelectState};

#[global_allocator]
static ALLOC: zeroizing_alloc::ZeroAlloc<std::alloc::System> =
    zeroizing_alloc::ZeroAlloc(std::alloc::System);

#[derive(Parser)]
struct Args {
    #[clap(long, num_args = 1..)]
    export: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut terminal = ratatui::init();
    let _guard = defer(ratatui::restore);

    let mut app = App::new(args);
    let mut event_stream = event::EventStream::new();
    let mut sleep = pin::pin!(None::<tokio::time::Sleep>);

    loop {
        app.update().await?;

        terminal.draw(|frame| app.render(frame))?;

        let f = futures::future::select(
            event_stream.next(),
            if let Some(sleep) = sleep.as_mut().as_pin_mut() {
                sleep.left_future()
            } else {
                future::pending().right_future()
            },
        );
        match f.await {
            futures::future::Either::Left((Some(event), _)) => {
                if app.handle(event?).is_break() {
                    break;
                }
                sleep.set(Some(tokio::time::sleep(Duration::from_secs(60))));
            }
            futures::future::Either::Left((None, _)) => break,
            futures::future::Either::Right(_) => {
                app.password.set_value(String::new());
                app.key.set_masked(true);
                app.event |= Event::PASSWORD_EDIT;
                sleep.set(None);
            }
        }
    }

    Ok(())
}

struct App {
    args: Args,
    argon2: Argon2<'static>,

    password: InputState,
    hash_actual: OutputState,
    hash_expected: InputState,
    algorithm: SelectState<s2k::Algorithm>,
    salt: InputState,
    key: OutputState,

    event: Event,

    cursor: Cursor,
    editing: bool,
}

bitflags::bitflags! {
    pub struct Event: u8 {
        const PASSWORD_EDIT = 1 << 0;
        const HASH_ACTUAL_SAVE = 1 << 1;
        const HASH_EXPECTED_EDIT = 1 << 2;
        const HASH_EXPECTED_LOAD = 1 << 3;
        const ALGORITHM_EDIT = 1 << 4;
        const SALT_EDIT = 1 << 5;
        const KEY_EXPORT = 1 << 6;
    }
}

#[derive(Clone, Copy, strum::FromRepr)]
enum Cursor {
    PasswordEdit,
    HashActualSave,
    HashExpectedEdit,
    HashExpectedLoad,
    AlgorithmEdit,
    SaltEdit,
    KeyToggleMasked,
    KeyExport,
}

impl App {
    fn new(args: Args) -> Self {
        Self {
            args,
            argon2: Argon2::default(),

            password: InputState::default().with_masked(true),
            hash_actual: OutputState::default(),
            hash_expected: InputState::default(),
            algorithm: SelectState::default(),
            salt: InputState::default(),
            key: OutputState::default().with_masked(true),

            event: Event::PASSWORD_EDIT
                | Event::HASH_EXPECTED_EDIT
                | Event::ALGORITHM_EDIT
                | Event::SALT_EDIT,

            cursor: Cursor::PasswordEdit,
            editing: false,
        }
    }

    async fn update(&mut self) -> anyhow::Result<()> {
        if self.event.intersects(Event::PASSWORD_EDIT) {
            self.hash_actual.set_value(Some(
                self.argon2
                    .hash_password(
                        self.password.value().as_bytes(),
                        &SaltString::generate(&mut OsRng),
                    )?
                    .to_string(),
            ));
        }

        if self.event.intersects(Event::HASH_ACTUAL_SAVE)
            && let Some(value) = self.hash_actual.value()
        {
            let path = Data::path()?;
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(
                path,
                serde_json::to_string_pretty(&Data {
                    hash: value.to_owned(),
                })?,
            )
            .await?;
        }

        if self.event.intersects(Event::HASH_EXPECTED_LOAD) {
            let path = Data::path()?;
            match tokio::fs::read(path).await {
                Ok(data) => {
                    let data = serde_json::from_slice::<Data>(&data)?;
                    self.hash_expected.set_value(data.hash);
                    self.event |= Event::HASH_EXPECTED_EDIT;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => Err(e)?,
            }
        }

        if self
            .event
            .intersects(Event::PASSWORD_EDIT | Event::HASH_EXPECTED_EDIT)
        {
            let validation = PasswordHash::new(self.hash_expected.value()).map(|value| {
                self.argon2
                    .verify_password(self.password.value().as_bytes(), &value)
            });
            self.password
                .set_validation(validation.as_ref().map(Result::as_ref).ok());
            self.hash_expected.set_validation(Some(validation.as_ref()));
        }

        if self
            .event
            .intersects(Event::PASSWORD_EDIT | Event::ALGORITHM_EDIT | Event::SALT_EDIT)
        {
            let (validation, key) = match self.algorithm.value().key(
                &self.argon2,
                self.password.value(),
                self.salt.value(),
            ) {
                Ok(key) => (Ok(()), Some(key)),
                Err(e @ (argon2::Error::SaltTooShort | argon2::Error::SaltTooLong)) => {
                    (Err(e), None)
                }
                Err(e) => Err(e)?,
            };
            self.salt.set_validation(Some(validation));
            self.key.set_value(key);
        }

        if self.event.intersects(Event::KEY_EXPORT)
            && let Some([program, args @ ..]) = self.args.export.as_deref()
            && let Some(value) = self.key.value()
        {
            let mut child = tokio::process::Command::new(program)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let mut stdin = child.stdin.take().unwrap();

            let (output, _) = tokio::time::timeout(
                Duration::from_secs(1),
                futures::future::try_join(child.wait_with_output(), async move {
                    stdin.write_all(value.as_bytes()).await?;
                    stdin.flush().await?;
                    Ok(())
                }),
            )
            .await??;
            anyhow::ensure!(output.status.success(), "{output:?}");
        }

        self.event.clear();
        Ok(())
    }

    fn handle(&mut self, event: event::Event) -> ControlFlow<()> {
        match (self.cursor, self.editing, event) {
            (
                _,
                _,
                event::Event::Key(event::KeyEvent {
                    code: event::KeyCode::Char('c'),
                    modifiers: event::KeyModifiers::CONTROL,
                    kind: event::KeyEventKind::Press | event::KeyEventKind::Repeat,
                    ..
                }),
            ) => ControlFlow::Break(()),
            (_, false, crate::key!(UP) | crate::key!(LEFT)) => {
                if let Some(c) = (self.cursor as usize)
                    .checked_sub(1)
                    .and_then(Cursor::from_repr)
                {
                    self.cursor = c;
                }
                ControlFlow::Continue(())
            }
            (_, false, crate::key!(DOWN) | crate::key!(RIGHT)) => {
                if let Some(c) = (self.cursor as usize)
                    .checked_add(1)
                    .and_then(Cursor::from_repr)
                {
                    self.cursor = c;
                }
                ControlFlow::Continue(())
            }
            (
                Cursor::PasswordEdit
                | Cursor::HashExpectedEdit
                | Cursor::AlgorithmEdit
                | Cursor::SaltEdit,
                false,
                crate::key!(ENTER),
            ) => {
                self.editing = true;
                ControlFlow::Continue(())
            }
            (Cursor::PasswordEdit, true, event) => {
                if self.password.handle(event).is_break() {
                    self.event |= Event::PASSWORD_EDIT;
                    self.editing = false;
                }
                ControlFlow::Continue(())
            }
            (Cursor::HashActualSave, _, crate::key!(ENTER)) => {
                self.event |= Event::HASH_ACTUAL_SAVE;
                ControlFlow::Continue(())
            }
            (Cursor::HashExpectedEdit, true, event) => {
                if self.hash_expected.handle(event).is_break() {
                    self.event |= Event::HASH_EXPECTED_EDIT;
                    self.editing = false;
                }
                ControlFlow::Continue(())
            }
            (Cursor::HashExpectedLoad, _, crate::key!(ENTER)) => {
                self.event |= Event::HASH_EXPECTED_LOAD;
                ControlFlow::Continue(())
            }
            (Cursor::AlgorithmEdit, true, event) => {
                if self.algorithm.handle(event).is_break() {
                    self.event |= Event::ALGORITHM_EDIT;
                    self.editing = false;
                }
                ControlFlow::Continue(())
            }
            (Cursor::SaltEdit, true, event) => {
                if self.salt.handle(event).is_break() {
                    self.event |= Event::SALT_EDIT;
                    self.editing = false;
                }
                ControlFlow::Continue(())
            }
            (Cursor::KeyToggleMasked, _, crate::key!(ENTER)) => {
                self.key.set_masked(!self.key.masked());
                ControlFlow::Continue(())
            }
            (Cursor::KeyExport, _, crate::key!(ENTER)) => {
                self.event |= Event::KEY_EXPORT;
                ControlFlow::Continue(())
            }
            _ => ControlFlow::Continue(()),
        }
    }

    fn render(&mut self, frame: &mut ratatui::Frame) {
        let password = Input::new(&mut self.password, "password")
            .editing(matches!(self.cursor, Cursor::PasswordEdit) && self.editing)
            .actions([(
                "edit",
                matches!(self.cursor, Cursor::PasswordEdit) && !self.editing,
            )]);
        let hash_actual = Output::new(&mut self.hash_actual, "hash (actual)")
            .actions([("save", matches!(self.cursor, Cursor::HashActualSave))]);
        let hash_expected = Input::new(&mut self.hash_expected, "hash (expected)")
            .editing(matches!(self.cursor, Cursor::HashExpectedEdit) && self.editing)
            .actions([
                (
                    "edit",
                    matches!(self.cursor, Cursor::HashExpectedEdit) && !self.editing,
                ),
                ("load", matches!(self.cursor, Cursor::HashExpectedLoad)),
            ]);
        let algorithm = Select::new(&mut self.algorithm, "algorithm")
            .editing(matches!(self.cursor, Cursor::AlgorithmEdit) && self.editing)
            .actions([(
                "edit",
                matches!(self.cursor, Cursor::AlgorithmEdit) && !self.editing,
            )]);
        let salt = Input::new(&mut self.salt, "salt")
            .editing(matches!(self.cursor, Cursor::SaltEdit) && self.editing)
            .actions([(
                "edit",
                matches!(self.cursor, Cursor::SaltEdit) && !self.editing,
            )]);
        let key = {
            let actions = [
                (
                    if self.key.masked() { "show" } else { "hide" },
                    matches!(self.cursor, Cursor::KeyToggleMasked),
                ),
                ("export", matches!(self.cursor, Cursor::KeyExport)),
            ];
            Output::new(&mut self.key, "key").actions(actions)
        };

        let [
            area_password,
            area_hash_actual,
            area_hash_expected,
            area_algorithm,
            area_salt,
            area_key,
        ] = layout::Layout::vertical([
            password.vertical(),
            hash_actual.vertical(),
            hash_expected.vertical(),
            algorithm.vertical(),
            salt.vertical(),
            key.vertical(),
        ])
        .flex(layout::Flex::Start)
        .areas(frame.area());

        password.render(frame, area_password);
        hash_actual.render(frame, area_hash_actual);
        hash_expected.render(frame, area_hash_expected);
        algorithm.render(frame, area_algorithm);
        salt.render(frame, area_salt);
        key.render(frame, area_key);
    }
}

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

#[derive(serde::Deserialize, serde::Serialize)]
struct Data {
    hash: String,
}

impl Data {
    fn path() -> anyhow::Result<PathBuf> {
        let data_dir = dirs::data_dir().ok_or_else(|| anyhow::format_err!("missing data dir"))?;
        Ok(data_dir.join(env!("CARGO_BIN_NAME")).with_extension("json"))
    }
}
