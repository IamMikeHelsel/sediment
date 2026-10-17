use crate::archive::{self, ArchiveInfo};
use eframe::egui::{self, Color32, RichText, Vec2};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

const ORANGE: Color32 = Color32::from_rgb(255, 79, 26);
const CONTROL_INK: Color32 = Color32::from_rgb(22, 22, 22);
#[derive(Clone, Copy)]
struct Palette {
    surface: Color32,
    ink: Color32,
    muted: Color32,
    line: Color32,
    field: Color32,
}
impl Palette {
    fn for_theme(theme: egui::Theme) -> Self {
        let rgb = |n: u32| Color32::from_rgb((n >> 16) as u8, (n >> 8) as u8, n as u8);
        let (surface, ink, muted, line, field) = match theme {
            egui::Theme::Light => (0xe2e2e0, 0x161616, 0x535351, 0xbdbdbb, 0xd6d6d4),
            egui::Theme::Dark => (0x181818, 0xf1f1ef, 0xb5b5b0, 0x454543, 0x292928),
        };
        Self {
            surface: rgb(surface),
            ink: rgb(ink),
            muted: rgb(muted),
            line: rgb(line),
            field: rgb(field),
        }
    }
}
fn utility(text: impl Into<String>, color: Color32) -> RichText {
    RichText::new(text).monospace().size(10.0).color(color)
}
fn primary(text: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(text).color(CONTROL_INK)).fill(ORANGE)
}
fn configure_theme(ctx: &egui::Context) {
    for theme in [egui::Theme::Light, egui::Theme::Dark] {
        let p = Palette::for_theme(theme);
        let mut style = (*ctx.style_of(theme)).clone();
        style.visuals = match theme {
            egui::Theme::Light => egui::Visuals::light(),
            egui::Theme::Dark => egui::Visuals::dark(),
        };
        style.visuals.override_text_color = Some(p.ink);
        style.visuals.panel_fill = p.surface;
        style.visuals.window_fill = p.surface;
        style.visuals.extreme_bg_color = p.field;
        style.visuals.faint_bg_color = p.field;
        style.visuals.window_corner_radius = 4.into();
        style.visuals.selection.bg_fill = ORANGE;
        style.visuals.selection.stroke = egui::Stroke::new(1.0, CONTROL_INK);
        for widget in [
            &mut style.visuals.widgets.noninteractive,
            &mut style.visuals.widgets.inactive,
            &mut style.visuals.widgets.hovered,
            &mut style.visuals.widgets.active,
        ] {
            widget.bg_fill = p.field;
            widget.weak_bg_fill = p.field;
            widget.bg_stroke = egui::Stroke::new(1.0, p.line);
            widget.fg_stroke = egui::Stroke::new(1.0, p.ink);
            widget.corner_radius = 3.into();
        }
        style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, p.ink);
        style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        style.spacing.button_padding = Vec2::new(12.0, 7.0);
        style.spacing.interact_size.y = 28.0;
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(13.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(12.0));
        ctx.set_style_of(theme, style);
    }
}

enum Outcome {
    Open(PathBuf, ArchiveInfo),
    Done(String),
    Created(PathBuf, ArchiveInfo),
    SavedWithoutPreview(PathBuf, String),
}
enum JobFailure {
    Cancelled,
    Failed(String),
    Panicked,
}
struct Job {
    receiver: Receiver<Result<Outcome, JobFailure>>,
    control: archive::OperationControl,
}
#[derive(Default)]
struct FilterCache {
    names: Vec<String>,
    query: Option<String>,
    indices: Vec<usize>,
    rebuilds: usize,
}
impl FilterCache {
    fn refresh(&mut self, info: &ArchiveInfo, filter: &str) {
        if self.query.as_deref() == Some(filter) {
            return;
        }
        if self.query.is_none() {
            self.names = info.entries.iter().map(|e| e.name.to_lowercase()).collect();
        }
        let query = filter.to_lowercase();
        self.indices.clear();
        self.indices.extend(
            self.names
                .iter()
                .enumerate()
                .filter_map(|(i, name)| name.contains(&query).then_some(i)),
        );
        self.query = Some(filter.to_owned());
        self.rebuilds += 1;
    }
}
fn dropped_archive(path: &std::path::Path) -> bool {
    path.extension().is_some_and(|e| {
        [
            "zip", "tar", "gz", "tgz", "rar", "7z", "bz2", "xz", "zst", "cab", "iso",
        ]
        .iter()
        .any(|x| e.to_string_lossy().eq_ignore_ascii_case(x))
    })
}
struct Sediment {
    path: Option<PathBuf>,
    info: Option<ArchiveInfo>,
    filter: String,
    job: Option<Job>,
    status: String,
    error: bool,
    create: bool,
    inputs: Vec<PathBuf>,
    theme: egui::ThemePreference,
    expanded: bool,
    status_details: bool,
    closing: bool,
    cache: FilterCache,
}

pub fn run(initial: Option<PathBuf>) -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_icon(egui::IconData {
                rgba: include_bytes!("../assets/icon-64.rgba").to_vec(),
                width: 64,
                height: 64,
            })
            .with_inner_size([600.0, 420.0])
            .with_min_inner_size([560.0, 380.0]),
        ..Default::default()
    };
    eframe::run_native(
        "sediment",
        options,
        Box::new(move |cc| {
            configure_theme(&cc.egui_ctx);
            cc.egui_ctx.set_theme(egui::ThemePreference::System);
            let mut app = Sediment {
                path: None,
                info: None,
                filter: String::new(),
                job: None,
                status: "Ready when you are.".into(),
                error: false,
                create: false,
                inputs: vec![],
                theme: egui::ThemePreference::System,
                expanded: false,
                status_details: false,
                closing: false,
                cache: FilterCache::default(),
            };
            if let Some(path) = initial {
                app.open(path, &cc.egui_ctx);
            }
            Ok(Box::new(app))
        }),
    )
}

fn preview_saved_archive(path: PathBuf) -> Outcome {
    match archive::inspect(&path) {
        Ok(info) => Outcome::Created(path, info),
        Err(error) => Outcome::SavedWithoutPreview(path, format!("{error:#}")),
    }
}

fn zip_destination(mut path: PathBuf) -> PathBuf {
    if !path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
    {
        let mut name = path.into_os_string();
        name.push(".zip");
        path = PathBuf::from(name);
    }
    path
}
fn extraction_destination(parent: &std::path::Path, archive: &std::path::Path) -> PathBuf {
    let filename = archive.file_name().unwrap_or_default().to_string_lossy();
    let lowercase = filename.to_ascii_lowercase();
    let stem = [".tar.gz", ".tgz", ".zip", ".tar"]
        .into_iter()
        .find(|suffix| lowercase.ends_with(suffix))
        .map(|suffix| &filename[..filename.len() - suffix.len()])
        .unwrap_or_else(|| {
            archive
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("Extracted")
        });
    let stem = if stem.trim().is_empty() || stem == "." || stem == ".." {
        "Extracted"
    } else {
        stem
    };
    let mut destination = parent.join(stem);
    let mut suffix = 2;
    while destination.symlink_metadata().is_ok() {
        destination = parent.join(format!("{stem} {suffix}"));
        suffix += 1;
    }
    destination
}

fn size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / 1048576.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1073741824.0)
    }
}
fn strata(ui: &mut egui::Ui, scale: f32, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(scale), egui::Sense::hover());
    for i in 0..3 {
        let y = rect.top() + scale * (0.22 + i as f32 * 0.23);
        let points = vec![
            egui::pos2(rect.left() + scale * 0.08, y),
            egui::pos2(rect.center().x, y + scale * 0.16),
            egui::pos2(rect.right() - scale * 0.08, y),
        ];
        ui.painter().add(egui::Shape::line(
            points,
            egui::Stroke::new(scale * 0.065, color),
        ));
    }
}
impl Sediment {
    fn start(
        &mut self,
        ctx: &egui::Context,
        kind: &'static str,
        label: &str,
        work: impl FnOnce(&archive::OperationControl) -> anyhow::Result<Outcome> + Send + 'static,
    ) {
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        let control = archive::OperationControl::default();
        self.job = Some(Job {
            receiver: rx,
            control: control.clone(),
        });
        self.status = label.into();
        self.error = false;
        thread::spawn(move || {
            let started = Instant::now();
            let span = tracing::info_span!("archive_job", operation = kind);
            let _entered = span.enter();
            let result = match catch_unwind(AssertUnwindSafe(|| work(&control))) {
                Ok(Ok(outcome)) => Ok(outcome),
                Ok(Err(error)) if error.is::<archive::Cancelled>() => Err(JobFailure::Cancelled),
                Ok(Err(error)) => Err(JobFailure::Failed(format!("{error:#}"))),
                Err(_) => Err(JobFailure::Panicked),
            };
            let outcome = match &result {
                Ok(_) => "success",
                Err(JobFailure::Cancelled) => "cancelled",
                Err(_) => "failure",
            };
            tracing::info!(
                elapsed_ms = started.elapsed().as_millis() as u64,
                outcome,
                "archive job finished"
            );
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }
    fn cancel_job(&mut self) {
        if let Some(job) = &self.job {
            job.control.cancel();
            self.status = "Cancelling… waiting for cleanup.".into();
        }
    }
    fn intercept_close(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.viewport().close_requested()) && self.job.is_some() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.closing = true;
            self.cancel_job();
        }
    }
    fn poll_job(&mut self, ctx: &egui::Context) {
        let result = self.job.as_ref().map(|job| job.receiver.try_recv());
        match result {
            Some(Ok(result)) => {
                self.job = None;
                if matches!(&result, Ok(Outcome::Created(..))) {
                    self.inputs.clear();
                }
                match result {
                    Ok(Outcome::Open(path, info)) | Ok(Outcome::Created(path, info)) => {
                        self.status = format!("{} entries · archive ready", info.entries.len());
                        self.path = Some(path);
                        self.info = Some(info);
                        self.filter.clear();
                        self.cache = FilterCache::default();
                        self.create = false;
                    }
                    Ok(Outcome::SavedWithoutPreview(path, error)) => {
                        self.status = format!(
                            "Archive saved to {}. Preview unavailable: {error}",
                            path.display()
                        );
                        self.path = None;
                        self.info = None;
                        self.cache = FilterCache::default();
                        self.inputs.clear();
                        self.create = false;
                        self.error = false;
                    }
                    Ok(Outcome::Done(message)) => self.status = message,
                    Err(JobFailure::Cancelled) => {
                        self.status = "Cancelled · temporary output cleaned up.".into();
                        self.error = false;
                    }
                    Err(JobFailure::Failed(error)) => {
                        self.status = error;
                        self.error = true;
                    }
                    Err(JobFailure::Panicked) => {
                        self.status = "The operation stopped unexpectedly. Temporary output cleanup was attempted; please retry.".into();
                        self.error = true;
                    }
                }
            }
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                self.job = None;
                self.error = true;
                self.status = "The worker stopped unexpectedly. Please retry.".into();
            }
            _ => {}
        }
        if let Some(job) = &self.job {
            if !job.control.is_cancelled() {
                let progress = job.control.snapshot();
                if !progress.phase.is_empty() {
                    self.status = format!(
                        "{} / {} entries / {}{}",
                        progress.phase,
                        progress.entries,
                        size(progress.bytes),
                        progress
                            .total_bytes
                            .map(|total| format!(" of {}", size(total)))
                            .unwrap_or_default()
                    );
                }
            }
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        if self.closing && self.job.is_none() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
    fn open(&mut self, path: PathBuf, ctx: &egui::Context) {
        self.start(ctx, "inspect", "Reading archive…", move |control| {
            let info = archive::inspect_with_control(&path, control)?;
            Ok(Outcome::Open(path, info))
        });
    }
    fn create_archive(&mut self, path: PathBuf, ctx: &egui::Context) {
        let path = zip_destination(path);
        let inputs = self.inputs.clone();
        self.start(ctx, "create", "Creating ZIP archive…", move |control| {
            archive::create_zip_with_control(&inputs, &path, control)?;
            Ok(preview_saved_archive(path))
        });
    }
    fn extract_archive(&mut self, path: PathBuf, parent: PathBuf, ctx: &egui::Context) {
        let dest = extraction_destination(&parent, &path);
        self.start(ctx, "extract", "Extracting files…", move |control| {
            let count = archive::extract_with_control(&path, &dest, control)?;
            Ok(Outcome::Done(format!(
                "Extracted {count} entries to {}",
                dest.display()
            )))
        });
    }
    fn verify_archive(&mut self, path: PathBuf, ctx: &egui::Context) {
        self.start(
            ctx,
            "verify",
            "Testing archive integrity…",
            move |control| {
                let count = archive::verify_with_control(&path, control)?;
                Ok(Outcome::Done(format!(
                    "Archive verified · {count} entries checked"
                )))
            },
        );
    }
    fn pick_open(&mut self, ctx: &egui::Context) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Open an archive")
            .pick_file()
        {
            self.open(path, ctx);
        }
    }
    fn begin_collection(&mut self) {
        if !self.create {
            self.error = false;
            self.status = "Add files or folders, then save your ZIP.".into();
        }
        self.create = true;
    }
    fn handle_drop(&mut self, dropped: Vec<PathBuf>, ctx: &egui::Context) {
        if !dropped.is_empty() {
            let archive =
                dropped.len() == 1 && dropped[0].is_file() && dropped_archive(&dropped[0]);
            if archive && !self.create {
                self.open(dropped[0].clone(), ctx);
            } else {
                self.add_inputs(dropped);
                self.begin_collection();
            }
        }
    }
    fn add_inputs(&mut self, paths: Vec<PathBuf>) {
        for path in paths {
            if !self.inputs.contains(&path) {
                self.inputs.push(path);
            }
        }
    }
    fn create_window(&mut self, ctx: &egui::Context) {
        let p = Palette::for_theme(ctx.theme());
        let mut visible = self.create;
        egui::Window::new("Create ZIP")
            .open(&mut visible)
            .resizable(false)
            .collapsible(false)
            .default_width(440.0)
            .show(ctx, |ui| {
                ui.label(utility("COLLECTION / ZIP", p.muted));
                ui.label("Add files or folders to your archive.");
                ui.add_enabled_ui(self.job.is_none(), |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("Add files").clicked()
                            && let Some(paths) = rfd::FileDialog::new().pick_files()
                        {
                            self.add_inputs(paths);
                        }
                        if ui.button("Add folder").clicked()
                            && let Some(path) = rfd::FileDialog::new().pick_folder()
                        {
                            self.add_inputs(vec![path]);
                        }
                    });
                    ui.separator();
                    let mut remove = None;
                    egui::ScrollArea::vertical()
                        .max_height(105.0)
                        .min_scrolled_height(55.0)
                        .show(ui, |ui| {
                            if self.inputs.is_empty() {
                                ui.label(RichText::new("No files added yet.").color(p.muted));
                            }
                            for (i, path) in self.inputs.iter().enumerate() {
                                ui.horizontal(|ui| {
                                    if ui
                                        .small_button("×")
                                        .on_hover_text("Remove from collection")
                                        .clicked()
                                    {
                                        remove = Some(i);
                                    }
                                    ui.add(
                                        egui::Label::new(
                                            path.file_name().unwrap_or_default().to_string_lossy(),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(path.display().to_string());
                                });
                            }
                        });
                    if let Some(i) = remove {
                        self.inputs.remove(i);
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(utility(format!("{} ITEMS", self.inputs.len()), p.muted));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .add_enabled(!self.inputs.is_empty(), primary("Save ZIP…"))
                                .clicked()
                                && let Some(path) = rfd::FileDialog::new()
                                    .set_title("Save ZIP archive")
                                    .set_file_name("Archive.zip")
                                    .add_filter("ZIP archive", &["zip"])
                                    .save_file()
                            {
                                self.create_archive(path, ctx);
                            }
                        });
                    });
                });
                if self.job.is_some() {
                    ui.horizontal(|ui| {
                        ui.label(utility("…", ORANGE));
                        ui.add(egui::Label::new(&self.status).truncate());
                    });
                }
                if self.error {
                    ui.add(egui::Label::new(&self.status).truncate())
                        .on_hover_text(&self.status);
                }
            });
        self.create = visible;
    }
}
impl eframe::App for Sediment {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.intercept_close(ctx);
        self.poll_job(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_job(&ctx);
        self.intercept_close(&ctx);
        if self.job.is_none() {
            let dropped: Vec<_> = ctx.input(|i| {
                i.raw
                    .dropped_files
                    .iter()
                    .map(|f| f.path().to_path_buf())
                    .collect()
            });
            self.handle_drop(dropped, &ctx);
            if ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::O)) {
                self.pick_open(&ctx);
            }
        }
        if self.info.is_some() && !self.expanded {
            let current = ctx
                .input(|i| i.viewport().inner_rect.map(|r| r.size()))
                .unwrap_or_default();
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(
                current.max(Vec2::new(760.0, 540.0)),
            ));
            self.expanded = true;
        }
        let p = Palette::for_theme(ctx.theme());
        egui::Panel::top("header")
            .frame(egui::Frame::new().fill(p.surface).inner_margin(16))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    strata(ui, 23.0, p.ink);
                    ui.label(RichText::new("sediment").size(20.0).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        egui::ComboBox::from_id_salt("appearance")
                            .width(73.0)
                            .selected_text(utility(
                                match self.theme {
                                    egui::ThemePreference::System => "SYSTEM",
                                    egui::ThemePreference::Light => "LIGHT",
                                    egui::ThemePreference::Dark => "DARK",
                                },
                                p.muted,
                            ))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.theme,
                                    egui::ThemePreference::System,
                                    "System",
                                );
                                ui.selectable_value(
                                    &mut self.theme,
                                    egui::ThemePreference::Light,
                                    "Light",
                                );
                                ui.selectable_value(
                                    &mut self.theme,
                                    egui::ThemePreference::Dark,
                                    "Dark",
                                );
                            });
                        ctx.set_theme(self.theme);
                        ui.add_enabled_ui(self.job.is_none(), |ui| {
                            if ui.button("Create ZIP").clicked() {
                                self.begin_collection();
                            }
                            if ui
                                .button("Open…")
                                .on_hover_text("Open archive (⌘O / Ctrl+O)")
                                .clicked()
                            {
                                self.pick_open(&ctx);
                            }
                        });
                    });
                });
            });
        egui::Panel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(p.surface)
                    .inner_margin(egui::Margin::symmetric(16, 10)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if self.job.is_some() {
                        ui.label(utility("…", ORANGE));
                    } else {
                        let (rect, _) =
                            ui.allocate_exact_size(Vec2::splat(7.0), egui::Sense::hover());
                        ui.painter().circle_filled(
                            rect.center(),
                            2.5,
                            if self.error { ORANGE } else { p.muted },
                        );
                    }
                    let status = if self.error {
                        format!("ERROR / {}", self.status)
                    } else {
                        self.status.clone()
                    };
                    let available = (ui.available_width()
                        - if self.job.is_some() { 145.0 } else { 72.0 })
                    .max(40.0);
                    ui.allocate_ui_with_layout(
                        Vec2::new(available, 20.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.add(egui::Label::new(utility(status, p.muted)).truncate())
                                .on_hover_text(&self.status);
                        },
                    );
                    if let Some(job) = &self.job
                        && ui
                            .add_enabled(!job.control.is_cancelled(), egui::Button::new("Cancel"))
                            .clicked()
                    {
                        self.cancel_job();
                    }
                    if ui.small_button("Details").clicked() {
                        self.status_details = true;
                    }
                });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(p.surface).inner_margin(16))
            .show(ui, |ui| {
                if let (Some(path), Some(info)) = (&self.path, &self.info) {
                    let path = path.clone();
                    ui.add(
                        egui::Label::new(
                            RichText::new(path.file_name().unwrap_or_default().to_string_lossy())
                                .size(21.0)
                                .strong(),
                        )
                        .truncate(),
                    )
                    .on_hover_text(path.display().to_string());
                    ui.label(utility(
                        format!(
                            "{} / {} ENTRIES / {} UNPACKED / {} STORED",
                            info.format.to_uppercase(),
                            info.entries.len(),
                            size(info.total_size),
                            size(info.compressed_size)
                        ),
                        p.muted,
                    ));
                    let mut extract = false;
                    let mut test = false;
                    ui.horizontal(|ui| {
                        ui.add_enabled_ui(self.job.is_none(), |ui| {
                            extract = ui.add(primary("Extract all…")).on_hover_text("Choose a parent folder. Files are extracted into a new archive-named subfolder.").clicked();
                            test = ui.button("Test archive").clicked();
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.filter)
                                    .hint_text("Filter files…")
                                    .desired_width(160.0),
                            );
                        });
                    });
                    ui.add_space(2.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(utility("CONTENTS", p.muted));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(utility("SIZE", p.muted));
                        });
                    });
                    ui.separator();
                    self.cache.refresh(info, &self.filter);
                    let entries = &self.cache.indices;
                    if entries.is_empty() {
                        ui.label(RichText::new(if info.entries.is_empty() { "This archive is empty." } else { "No matching files." }).color(p.muted));
                    }
                    egui::ScrollArea::vertical()
                        .max_height(ui.available_height())
                        .auto_shrink([false, false])
                        .show_rows(ui, 25.0, entries.len(), |ui, rows| {
                            for i in rows {
                                let entry = &info.entries[entries[i]];
                                ui.horizontal(|ui| {
                                    ui.add_sized(
                                        [14.0, 20.0],
                                        egui::Label::new(utility(
                                            if entry.is_dir { "+" } else { "·" },
                                            p.muted,
                                        )),
                                    );
                                    let width = (ui.available_width() - 90.0).max(100.0);
                                    ui.allocate_ui_with_layout(
                                        Vec2::new(width, 20.0),
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            ui.add(egui::Label::new(&entry.name).truncate())
                                                .on_hover_text(&entry.name);
                                        },
                                    );
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.label(utility(
                                                if entry.is_dir {
                                                    "—".into()
                                                } else {
                                                    size(entry.size)
                                                },
                                                p.muted,
                                            ))
                                            .on_hover_text(format!(
                                                "Stored: {}",
                                                size(entry.compressed_size)
                                            ));
                                        },
                                    );
                                });
                            }
                        });
                    if extract {
                        if let Some(dest) = rfd::FileDialog::new()
                            .set_title("Choose where to extract the archive")
                            .pick_folder()
                        {
                            self.extract_archive(path, dest, &ctx);
                        }
                    } else if test {
                        self.verify_archive(path, &ctx);
                    }
                } else {
                    ui.add_space((ui.available_height() * 0.13).max(6.0));
                    ui.label(utility("LOCAL ARCHIVE UTILITY", p.muted));
                    ui.add_space(5.0);
                    ui.label(
                        RichText::new("Less space.\nEverything in place.")
                            .size(30.0)
                            .strong(),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Drop an archive here, or gather files into a ZIP.")
                            .color(p.muted),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(self.job.is_none(), primary("Open archive…"))
                            .clicked()
                        {
                            self.pick_open(&ctx);
                        }
                        ui.label(utility("ZIP / TAR / TAR.GZ", p.muted));
                    });
                }
            });
        if self.create {
            self.create_window(&ctx);
        }
        if self.status_details {
            egui::Window::new("Operation details")
                .open(&mut self.status_details)
                .default_width(440.0)
                .resizable(true)
                .show(&ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(180.0)
                        .show(ui, |ui| {
                            ui.add(egui::Label::new(&self.status).wrap().selectable(true));
                        });
                    if ui.button("Copy details").clicked() {
                        ctx.copy_text(self.status.clone());
                    }
                });
        }
    }
}

#[cfg(all(test, feature = "gui-test"))]
mod visual_tests {
    use super::*;
    use crate::archive::Entry;
    use egui_kittest::kittest::Queryable as _;

    fn test_harness() -> egui_kittest::Harness<'static, Sediment> {
        egui_kittest::Harness::builder()
            .with_size([560.0, 380.0])
            .build_eframe(|cc| {
                configure_theme(&cc.egui_ctx);
                Sediment {
                    path: None,
                    info: None,
                    filter: String::new(),
                    job: None,
                    status: "Ready".into(),
                    error: false,
                    create: false,
                    inputs: vec![],
                    theme: egui::ThemePreference::Light,
                    expanded: true,
                    status_details: false,
                    closing: false,
                    cache: FilterCache::default(),
                }
            })
    }
    fn wait_for_worker(harness: &mut egui_kittest::Harness<'_, Sediment>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while harness.state().job.is_some() && Instant::now() < deadline {
            harness.step();
            thread::sleep(Duration::from_millis(2));
        }
        harness.step();
        assert!(harness.state().job.is_none(), "worker did not finish");
    }
    #[test]
    fn worker_create_preview_verify_extract_journey_preserves_payload() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("旅 notes.txt");
        let payload = b"Independent roundtrip payload: sediment\n";
        std::fs::write(&input, payload).unwrap();
        let mut harness = test_harness();
        harness.state_mut().inputs = vec![input];
        harness.state_mut().create = true;
        harness
            .state_mut()
            .create_archive(dir.path().join("Collection"), &egui::Context::default());
        wait_for_worker(&mut harness);
        assert!(!harness.state().error, "{}", harness.state().status);
        let archive = dir.path().join("Collection.zip");
        assert_eq!(harness.state().path.as_ref(), Some(&archive));
        assert!(harness.state().inputs.is_empty());
        assert!(!harness.state().create);
        assert_eq!(harness.state().info.as_ref().unwrap().entries.len(), 1);
        harness
            .state_mut()
            .verify_archive(archive.clone(), &egui::Context::default());
        wait_for_worker(&mut harness);
        assert!(!harness.state().error);
        assert!(harness.state().status.starts_with("Archive verified"));
        let existing = dir.path().join("Collection");
        std::fs::create_dir(&existing).unwrap();
        std::fs::write(existing.join("keep.txt"), b"preserve existing").unwrap();
        harness
            .state_mut()
            .extract_archive(archive, dir.path().into(), &egui::Context::default());
        wait_for_worker(&mut harness);
        assert!(!harness.state().error, "{}", harness.state().status);
        assert_eq!(
            std::fs::read(dir.path().join("Collection 2/旅 notes.txt")).unwrap(),
            payload
        );
        assert_eq!(
            std::fs::read(existing.join("keep.txt")).unwrap(),
            b"preserve existing"
        );
    }
    #[test]
    fn starting_collection_clears_unrelated_error_and_retains_draft() {
        let mut harness = test_harness();
        harness.state_mut().error = true;
        harness.state_mut().status = "Unsupported RAR archive".into();
        harness.state_mut().inputs = vec!["draft.txt".into()];
        harness.run();
        harness.get_by_label("Create ZIP").click();
        harness.run();
        assert!(harness.state().create);
        assert!(!harness.state().error);
        assert_eq!(harness.state().inputs, vec![PathBuf::from("draft.txt")]);
    }
    #[test]
    fn extraction_names_handle_case_suffix_only_and_dangling_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            extraction_destination(dir.path(), std::path::Path::new("Capture.TAR.GZ")),
            dir.path().join("Capture")
        );
        assert_eq!(
            extraction_destination(dir.path(), std::path::Path::new(".zip")),
            dir.path().join("Extracted")
        );
        assert_eq!(
            extraction_destination(dir.path(), std::path::Path::new(".TAR.GZ")),
            dir.path().join("Extracted")
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.path().join("missing"), dir.path().join("Capture"))
                .unwrap();
            assert_eq!(
                extraction_destination(dir.path(), std::path::Path::new("Capture.TAR.GZ")),
                dir.path().join("Capture 2")
            );
        }
    }
    #[test]
    fn empty_archive_and_empty_filter_result_have_distinct_messages() {
        let mut harness = test_harness();
        harness.state_mut().path = Some("empty.zip".into());
        harness.state_mut().info = Some(ArchiveInfo {
            format: "ZIP".into(),
            entries: vec![],
            total_size: 0,
            compressed_size: 22,
        });
        harness.run();
        assert!(
            harness
                .query_all_by_value("This archive is empty.")
                .next()
                .is_some()
        );
        harness
            .state_mut()
            .info
            .as_mut()
            .unwrap()
            .entries
            .push(Entry {
                name: "file.txt".into(),
                size: 0,
                compressed_size: 0,
                is_dir: false,
            });
        harness.state_mut().cache = FilterCache::default();
        harness.state_mut().filter = "unmatched".into();
        harness.run();
        assert!(
            harness
                .query_all_by_value("No matching files.")
                .next()
                .is_some()
        );
    }

    #[test]
    fn cancelling_waits_for_worker_cleanup() {
        let mut harness = test_harness();
        let (tx, rx) = mpsc::channel();
        let control = archive::OperationControl::default();
        harness.state_mut().job = Some(Job {
            receiver: rx,
            control: control.clone(),
        });
        harness.step();
        harness.get_by_label("Cancel").click();
        harness.step();
        assert!(control.is_cancelled());
        assert!(
            harness.state().job.is_some(),
            "Cancellation must wait for cleanup acknowledgement"
        );
        tx.send(Err(JobFailure::Cancelled)).unwrap();
        harness.step();
        assert!(harness.state().job.is_none());
        assert!(!harness.state().error);
        assert!(harness.state().status.starts_with("Cancelled"));
    }
    #[test]
    fn saved_archive_preview_failure_is_not_reported_as_failed_creation() {
        let mut harness = test_harness();
        let (tx, rx) = mpsc::channel();
        harness.state_mut().create = true;
        harness.state_mut().job = Some(Job {
            receiver: rx,
            control: archive::OperationControl::default(),
        });
        let outcome =
            preview_saved_archive(PathBuf::from("/nonexistent/sediment-saved-preview.zip"));
        assert!(matches!(outcome, Outcome::SavedWithoutPreview(..)));
        tx.send(Ok(outcome)).unwrap();
        harness.step();
        assert!(harness.state().status.starts_with("Archive saved"));
        assert!(!harness.state().error);
        assert!(!harness.state().create);
    }
    #[test]
    fn close_request_cancels_and_waits_for_worker() {
        let mut harness = test_harness();
        let (tx, rx) = mpsc::channel();
        let control = archive::OperationControl::default();
        harness.state_mut().job = Some(Job {
            receiver: rx,
            control: control.clone(),
        });
        harness
            .input_mut()
            .viewports
            .entry(egui::ViewportId::ROOT)
            .or_default()
            .events
            .push(egui::ViewportEvent::Close);
        harness.step();
        assert!(harness.state().closing);
        assert!(control.is_cancelled());
        assert!(harness.state().job.is_some());
        tx.send(Err(JobFailure::Cancelled)).unwrap();
        harness.step();
        assert!(harness.state().job.is_none());
    }
    #[test]
    fn panicking_worker_reports_recoverable_error() {
        let mut harness = test_harness();
        harness
            .state_mut()
            .start(&egui::Context::default(), "test", "Testing", |_| {
                panic!("simulated worker fault")
            });
        for _ in 0..100 {
            harness.step();
            if harness.state().job.is_none() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(harness.state().job.is_none());
        assert!(harness.state().error);
        assert!(!harness.state().status.contains("simulated worker fault"));
    }
    #[test]
    fn cache_rebuilds_only_for_archive_or_changed_query() {
        let mut harness = test_harness();
        harness.state_mut().info = Some(ArchiveInfo {
            entries: vec![
                Entry {
                    name: "Alpha.txt".into(),
                    size: 4,
                    compressed_size: 4,
                    is_dir: false,
                },
                Entry {
                    name: "Beta.txt".into(),
                    size: 4,
                    compressed_size: 4,
                    is_dir: false,
                },
            ],
            format: "ZIP".into(),
            total_size: 8,
            compressed_size: 8,
        });
        harness.state_mut().path = Some("sample.zip".into());
        harness.run();
        let rebuilds = harness.state().cache.rebuilds;
        for _ in 0..5 {
            harness.step();
        }
        assert_eq!(harness.state().cache.rebuilds, rebuilds);
        harness
            .get_by_role(egui::accesskit::Role::TextInput)
            .click();
        harness.step();
        harness
            .get_by_role(egui::accesskit::Role::TextInput)
            .type_text("BETA");
        harness.run();
        assert_eq!(harness.state().cache.indices, vec![1]);
        assert_eq!(harness.state().cache.rebuilds, rebuilds + 1);
    }
    #[test]
    fn long_error_details_and_theme_are_accessible() {
        let mut harness = test_harness();
        harness.state_mut().error = true;
        harness.state_mut().status =
            "Unable to read archive: ".to_owned() + &"long/path/".repeat(80);
        harness.run();
        harness.get_by_role(egui::accesskit::Role::ComboBox).click();
        harness.run();
        harness.get_by_label("Dark").click();
        harness.run();
        assert_eq!(harness.state().theme, egui::ThemePreference::Dark);
        harness.get_by_label("Details").click();
        harness.run();
        assert!(harness.state().status_details);
        harness.get_by_label("Copy details").click();
        harness.run();
        assert!(harness.state().status.len() > 700);
    }
    #[test]
    fn unsupported_archive_drop_opens_instead_of_compressing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsupported.rar");
        std::fs::write(&path, b"Rar!\x1a\x07\x00").unwrap();
        let mut harness = test_harness();
        harness
            .state_mut()
            .handle_drop(vec![path], &egui::Context::default());
        assert!(harness.state().job.is_some());
        assert!(!harness.state().create);
        assert!(harness.state().inputs.is_empty());
        for _ in 0..100 {
            harness.step();
            if harness.state().job.is_none() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(harness.state().job.is_none());
        assert!(harness.state().error);
    }

    #[test]
    #[ignore = "Host-specific release-mode responsiveness measurement; no timing threshold"]
    fn benchmark_large_archive() {
        let mut harness = test_harness();
        harness.state_mut().path = Some("synthetic-100k.zip".into());
        harness.state_mut().info = Some(ArchiveInfo {
            format: "ZIP".into(),
            total_size: 100_000 * 1024,
            compressed_size: 100_000 * 512,
            entries: (0..100_000)
                .map(|index| Entry {
                    name: format!("synthetic/folder-{index:06}/item-{index:06}.txt"),
                    size: 1024,
                    compressed_size: 512,
                    is_dir: false,
                })
                .collect(),
        });
        let start = Instant::now();
        harness.run();
        let initial_layout_ms = start.elapsed().as_secs_f64() * 1000.0;
        let rebuilds = harness.state().cache.rebuilds;
        let mut idle_ms = Vec::new();
        for _ in 0..30 {
            let start = Instant::now();
            harness.step();
            idle_ms.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        idle_ms.sort_by(f64::total_cmp);
        assert_eq!(harness.state().cache.rebuilds, rebuilds);
        assert_eq!(harness.state().cache.indices.len(), 100_000);
        // Accessibility rows are generated by the actual virtualized table, not the entire archive.
        assert!(
            harness
                .query_all_by_value("synthetic/folder-000000/item-000000.txt")
                .next()
                .is_some()
        );
        assert!(
            harness
                .query_all_by_value("synthetic/folder-099999/item-099999.txt")
                .next()
                .is_none()
        );
        harness.state_mut().filter = "item-099999".into();
        let start = Instant::now();
        harness.run();
        let filtered_layout_ms = start.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(harness.state().cache.indices, vec![99_999]);
        assert!(
            harness
                .query_all_by_value("synthetic/folder-099999/item-099999.txt")
                .next()
                .is_some()
        );
        let start = Instant::now();
        harness.render().unwrap();
        let filtered_gpu_render_ms = start.elapsed().as_secs_f64() * 1000.0;
        let report = serde_json::json!({
            "schema": 1, "version": env!("CARGO_PKG_VERSION"), "entries": 100_000,
            "viewport": [560, 380], "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "host_os": std::env::consts::OS, "host_arch": std::env::consts::ARCH,
            "initial_cache_and_layout_ms": initial_layout_ms,
            "idle_frame_samples": idle_ms.len(), "idle_frame_median_ms": idle_ms[idle_ms.len()/2],
            "filtered_query_and_layout_ms": filtered_layout_ms,
            "filtered_gpu_render_with_renderer_initialization_ms": filtered_gpu_render_ms,
            "cache_rebuilds_after_idle": rebuilds, "filtered_matches": 1,
            "offscreen_row_absent_before_filter": true,
            "notes": "Synthetic test fixture only. Host-specific observations, no timing acceptance threshold. Run in release mode. Layout uses the real application and virtualized table; GPU measurement includes first-render initialization."
        });
        std::fs::create_dir_all("docs/evidence").unwrap();
        std::fs::write(
            "docs/evidence/ui-performance-0.1.2.json",
            serde_json::to_string_pretty(&report).unwrap(),
        )
        .unwrap();
        println!("{report}");
    }

    #[test]
    #[ignore = "Produces GPU-rendered review evidence; run explicitly on a graphics-capable host"]
    fn render_cassette_previews() {
        let output = std::path::Path::new(concat!(
            "docs/evidence/workflows-",
            env!("CARGO_PKG_VERSION")
        ));
        std::fs::create_dir_all(output).unwrap();
        for (name, dimensions, dark, archive, create) in [
            ("light-empty", [600.0, 420.0], false, false, false),
            ("dark-empty", [600.0, 420.0], true, false, false),
            ("light-archive", [760.0, 540.0], false, true, false),
            ("dark-archive", [760.0, 540.0], true, true, false),
            ("light-minimum", [560.0, 380.0], false, true, false),
            ("dark-create-minimum", [560.0, 380.0], true, false, true),
        ] {
            let theme = if dark {
                egui::ThemePreference::Dark
            } else {
                egui::ThemePreference::Light
            };
            let mut harness = egui_kittest::Harness::builder()
                .with_size(dimensions)
                .build_eframe(|cc| {
                    configure_theme(&cc.egui_ctx);
                    cc.egui_ctx.set_theme(theme);
                    Sediment {
                        path: archive.then(|| PathBuf::from("Field recordings.zip")),
                        info: archive.then(|| ArchiveInfo {
                            format: "ZIP".into(),
                            total_size: 18976000,
                            compressed_size: 12743000,
                            entries: vec![
                                Entry {
                                    name: "Field recordings/".into(),
                                    size: 0,
                                    compressed_size: 0,
                                    is_dir: true,
                                },
                                Entry {
                                    name: "Field recordings/01 — Morning static.wav".into(),
                                    size: 16384000,
                                    compressed_size: 11000000,
                                    is_dir: false,
                                },
                                Entry {
                                    name: "Field recordings/02 — Night drive.wav".into(),
                                    size: 2590720,
                                    compressed_size: 1741720,
                                    is_dir: false,
                                },
                                Entry {
                                    name: "Field recordings/session-notes.txt".into(),
                                    size: 1280,
                                    compressed_size: 1280,
                                    is_dir: false,
                                },
                            ],
                        }),
                        filter: String::new(),
                        job: None,
                        status: if archive {
                            "4 entries · archive opened"
                        } else {
                            "Ready when you are."
                        }
                        .into(),
                        error: false,
                        create,
                        inputs: if create {
                            vec![
                                PathBuf::from("Field recordings/session-notes.txt"),
                                PathBuf::from("Field recordings/takes"),
                            ]
                        } else {
                            vec![]
                        },
                        theme,
                        expanded: true,
                        status_details: false,
                        closing: false,
                        cache: FilterCache::default(),
                    }
                });
            harness.run();
            if name == "light-archive" {
                harness.get_by_role(egui::accesskit::Role::ComboBox).click();
                harness.run();
                harness.get_by_label("Dark").click();
                harness.run();
                assert_eq!(harness.state().theme, egui::ThemePreference::Dark);
                harness.get_by_role(egui::accesskit::Role::ComboBox).click();
                harness.run();
                harness.get_by_label("Light").click();
                harness.run();
                harness
                    .get_by_role(egui::accesskit::Role::TextInput)
                    .click();
                harness.run();
                harness
                    .get_by_role(egui::accesskit::Role::TextInput)
                    .type_text("session-notes");
                harness.run();
                assert_eq!(harness.state().filter, "session-notes");
                harness.get_by_label("Details").click();
                harness.run();
                assert!(harness.state().status_details);
                harness.state_mut().filter.clear();
                harness.state_mut().status_details = false;
                harness.run();
            }
            harness
                .render()
                .unwrap()
                .save(output.join(format!("{name}.png")))
                .unwrap();
        }
        let mut harness = test_harness();
        let (tx, rx) = mpsc::channel();
        harness.state_mut().job = Some(Job {
            receiver: rx,
            control: archive::OperationControl::default(),
        });
        harness.step();
        harness
            .render()
            .unwrap()
            .save(output.join("light-busy-minimum.png"))
            .unwrap();
        harness.get_by_label("Cancel").click();
        harness.step();
        harness.step();
        harness
            .render()
            .unwrap()
            .save(output.join("light-cancelling-minimum.png"))
            .unwrap();
        tx.send(Err(JobFailure::Cancelled)).unwrap();
        harness.step();
        harness.state_mut().error = true;
        harness.state_mut().status = "Unable to extract archive: a destination already exists. Choose a new destination folder and retry. No existing files were overwritten.".into();
        harness.state_mut().status_details = true;
        harness.run();
        harness
            .render()
            .unwrap()
            .save(output.join("light-error-details-minimum.png"))
            .unwrap();
    }
}
